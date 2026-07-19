#!/usr/bin/env python3
"""Fail-closed verifier for Venatr's digest-only public release authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "authority/policy.json"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
OID = re.compile(r"^[0-9a-f]{40}$")
PHASES = tuple(f"P{number}" for number in range(8))
EXPECTED_SIGNING = {
    "mode": "github_oidc_sigstore_public_good_keyless",
    "cost_model": "zero_monetary_service_cost",
    "issuer": "https://token.actions.githubusercontent.com",
    "certificate_identity": "https://github.com/sandmantesting/venatr-release-authority/.github/workflows/bootstrap-generation-zero.yml@refs/heads/main",
    "repository_id": 1305288232,
    "repository_owner_id": 306626219,
    "environment": "venatr-production-promotion",
    "workflow_path": ".github/workflows/bootstrap-generation-zero.yml",
    "qualification_workflow_path": ".github/workflows/verify-keyless-authority.yml",
    "trusted_root": "sigstore_public_good_tuf",
    "transparency_log": "rekor",
    "offline_bundle_required": True,
    "raw_private_key": "forbidden",
}
BANNED_SUFFIXES = {".7z", ".dll", ".env", ".exe", ".gz", ".pem", ".pfx", ".pyc", ".tar", ".whl", ".zip", ".zst"}
BANNED_CONTENT = (
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(rb"\b(?:gh[opusr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b"),
)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"object required: {path}")
    return value


def request_blockers(request: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    expected_keys = {
        "contract", "candidate_id", "generation", "source_repository", "source_revision",
        "source_tree", "source_archive_sha256", "release_definition_sha256",
        "material_snapshot_sha256", "release_set_sha256", "evidence_root_index_sha256",
        "role_assignments_sha256", "environment_assignments_sha256",
        "qualification_evidence", "previous_authority_state_sha256",
        "request_sha256",
    }
    if set(request) != expected_keys:
        blockers.append("REQUEST_FIELDS_INVALID")
    material = dict(request)
    claimed = material.pop("request_sha256", None)
    if claimed != digest(canonical(material)):
        blockers.append("REQUEST_HASH_INVALID")
    revision = str(request.get("source_revision") or "")
    archive = str(request.get("source_archive_sha256") or "")
    expected_id = f"venatr-{revision[:12]}-{archive.removeprefix('sha256:')[:12]}"
    if request.get("contract") != "venatr_release_candidate_request_v1":
        blockers.append("REQUEST_CONTRACT_INVALID")
    if request.get("source_repository") != policy.get("source_repository"):
        blockers.append("SOURCE_REPOSITORY_INVALID")
    if OID.fullmatch(revision) is None or OID.fullmatch(str(request.get("source_tree") or "")) is None:
        blockers.append("SOURCE_IDENTITY_INVALID")
    if request.get("candidate_id") != expected_id:
        blockers.append("CANDIDATE_ID_INVALID")
    for name in (
        "source_archive_sha256", "release_definition_sha256", "material_snapshot_sha256",
        "release_set_sha256", "evidence_root_index_sha256", "role_assignments_sha256",
        "environment_assignments_sha256",
    ):
        if SHA256.fullmatch(str(request.get(name) or "")) is None:
            blockers.append(f"DIGEST_INVALID:{name}")
    evidence = request.get("qualification_evidence")
    if not isinstance(evidence, dict) or set(evidence) != set(PHASES):
        blockers.append("QUALIFICATION_PHASE_SET_INVALID")
    else:
        for phase in PHASES:
            row = evidence.get(phase)
            if not isinstance(row, dict) or set(row) != {"manifest_sha256", "status"}:
                blockers.append(f"QUALIFICATION_EVIDENCE_INVALID:{phase}")
            elif row.get("status") != "passed" or SHA256.fullmatch(str(row.get("manifest_sha256") or "")) is None:
                blockers.append(f"QUALIFICATION_EVIDENCE_INVALID:{phase}")
    generation = request.get("generation")
    previous = request.get("previous_authority_state_sha256")
    if generation == 0 and previous is not None:
        blockers.append("GENESIS_PREDECESSOR_FORBIDDEN")
    elif isinstance(generation, int) and generation > 0 and SHA256.fullmatch(str(previous or "")) is None:
        blockers.append("PREDECESSOR_REQUIRED")
    elif not isinstance(generation, int) or generation < 0:
        blockers.append("GENERATION_INVALID")
    return sorted(set(blockers))


def policy_blockers(policy: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if policy.get("contract") != "venatr_public_release_authority_policy_v1":
        blockers.append("AUTHORITY_POLICY_CONTRACT_INVALID")
    if policy.get("status") != "ratified":
        blockers.append("AUTHORITY_POLICY_STATUS_INVALID")
    if policy.get("authority_repository") != "sandmantesting/venatr-release-authority":
        blockers.append("AUTHORITY_REPOSITORY_INVALID")
    if policy.get("source_repository") != "sandmantesting/Venatr":
        blockers.append("SOURCE_REPOSITORY_POLICY_INVALID")
    if policy.get("signing") != EXPECTED_SIGNING:
        blockers.append("SIGNING_AUTHORITY_POLICY_INVALID")
    if policy.get("administrator_bypass") != "forbidden" or policy.get("self_approval") != "forbidden":
        blockers.append("AUTHORITY_BYPASS_POLICY_INVALID")
    bootstrap = policy.get("bootstrap")
    if not isinstance(bootstrap, dict) or bootstrap.get("generation") != 0:
        blockers.append("BOOTSTRAP_POLICY_INVALID")
    elif bootstrap.get("previous_state") is not None or bootstrap.get("required_phases") != list(PHASES):
        blockers.append("BOOTSTRAP_POLICY_INVALID")
    return sorted(set(blockers))


def workflow_blockers(root: Path) -> list[str]:
    path = root / ".github/workflows/bootstrap-generation-zero.yml"
    if not path.is_file():
        return ["BOOTSTRAP_WORKFLOW_MISSING"]
    content = path.read_text(encoding="utf-8")
    required = (
        "environment: venatr-production-promotion",
        "runs-on: ubuntu-24.04",
        "attestations: write",
        "ref: main",
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
        "--bundle state/generation-0.sigstore.json",
        "--cert-oidc-issuer \"https://token.actions.githubusercontent.com\"",
        "--signer-digest \"$GITHUB_WORKFLOW_SHA\"",
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
    )
    forbidden = (
        "aws-actions/", "awskms://", "KMS_KEY_URI", "release-signing-root.pub",
        "sigstore/cosign", "--signer-workflow",
    )
    blockers = [f"BOOTSTRAP_WORKFLOW_REQUIREMENT_MISSING:{value}" for value in required if value not in content]
    blockers.extend(f"BOOTSTRAP_WORKFLOW_FORBIDDEN:{value}" for value in forbidden if value in content)
    return sorted(set(blockers))


def qualification_workflow_blockers(root: Path) -> list[str]:
    path = root / ".github/workflows/verify-keyless-authority.yml"
    if not path.is_file():
        return ["KEYLESS_QUALIFICATION_WORKFLOW_MISSING"]
    content = path.read_text(encoding="utf-8")
    required = (
        "environment: venatr-production-promotion",
        "runs-on: ubuntu-24.04",
        "attestations: write",
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
        "--cert-identity \"https://github.com/sandmantesting/venatr-release-authority/.github/workflows/verify-keyless-authority.yml@refs/heads/main\"",
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
        "verifiedTimestamps",
    )
    forbidden = ("aws-actions/", "awskms://", "KMS_KEY_URI", "sigstore/cosign", "--signer-workflow")
    blockers = [f"KEYLESS_QUALIFICATION_REQUIREMENT_MISSING:{value}" for value in required if value not in content]
    blockers.extend(f"KEYLESS_QUALIFICATION_FORBIDDEN:{value}" for value in forbidden if value in content)
    return sorted(set(blockers))


def action_pin_blockers(root: Path) -> list[str]:
    blockers: list[str] = []
    workflow_root = root / ".github/workflows"
    for path in sorted(workflow_root.glob("*.yml")):
        relative = path.relative_to(root).as_posix()
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = re.search(r"\buses:\s*([^\s#]+)", line)
            if match is None:
                continue
            reference = match.group(1)
            revision = reference.rsplit("@", 1)[-1] if "@" in reference else ""
            if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
                blockers.append(f"ACTION_NOT_SHA_PINNED:{relative}:{line_number}:{reference}")
    return sorted(set(blockers))


def hygiene_blockers(root: Path) -> list[str]:
    blockers: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/") or not path.is_file():
            continue
        if path.is_symlink():
            blockers.append(f"SYMLINK_FORBIDDEN:{relative}")
            continue
        size = path.stat().st_size
        if size > 1_048_576:
            blockers.append(f"PUBLIC_FILE_TOO_LARGE:{relative}")
            continue
        if path.suffix.lower() in BANNED_SUFFIXES:
            blockers.append(f"PUBLIC_FILE_TYPE_FORBIDDEN:{relative}")
        content = path.read_bytes()
        if any(pattern.search(content) for pattern in BANNED_CONTENT):
            blockers.append(f"PUBLIC_SECRET_PATTERN:{relative}")
    return sorted(set(blockers))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    policy = load(POLICY)
    blockers = hygiene_blockers(args.root.resolve())
    blockers.extend(policy_blockers(policy))
    blockers.extend(workflow_blockers(args.root.resolve()))
    blockers.extend(qualification_workflow_blockers(args.root.resolve()))
    blockers.extend(action_pin_blockers(args.root.resolve()))
    if args.request:
        blockers.extend(request_blockers(load(args.request.resolve()), policy))
    result = {"status": "passed" if not blockers else "blocked", "blockers": sorted(set(blockers))}
    print(json.dumps(result, sort_keys=True))
    return 0 if not blockers else 1


if __name__ == "__main__":
    raise SystemExit(main())
