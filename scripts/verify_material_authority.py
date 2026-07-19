"""Verify digest-only Venatr material-plan authority packets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
OID = re.compile(r"^[0-9a-f]{40}$")
ROLES = {"material-acquirer", "supply-chain-reviewer", "release-approver"}
PAIRS = {
    frozenset(("upstream-signing-authority", "controlled-reproducer")),
    frozenset(("sigstore-identity", "controlled-reproducer")),
    frozenset(("debian-archive-key", "controlled-reproducer")),
    frozenset(("vendor-signing-key", "controlled-reproducer")),
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"object required: {path}")
    return value


def safe_file(packet: Path, relative: Any) -> Path:
    text = str(relative or "")
    pure = PurePosixPath(text)
    if not text or pure.is_absolute() or ".." in pure.parts:
        raise ValueError(f"unsafe packet path: {text}")
    path = (packet / Path(*pure.parts)).resolve()
    if packet.resolve() not in path.parents or not path.is_file():
        raise ValueError(f"packet file missing: {text}")
    return path


def self_hash(value: dict[str, Any], field: str) -> str:
    material = dict(value)
    claimed = material.pop(field, None)
    actual = digest(canonical(material))
    if claimed != actual:
        raise ValueError(f"{field} invalid")
    return actual


def verify_packet(authority_path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    packet = authority_path.resolve().parent
    authority = load(authority_path)
    required = {
        "contract", "candidate_id", "source_revision", "source_tree", "candidate_plan_sha256",
        "trust_policy_sha256",
        "evidence_index", "evidence_index_sha256", "approval", "approval_sha256",
        "production_plan", "production_plan_sha256", "authority_sha256",
    }
    if set(authority) != required or authority.get("contract") != "venatr_material_plan_authority_v1":
        raise ValueError("material authority fields or contract invalid")
    self_hash(authority, "authority_sha256")
    if OID.fullmatch(str(authority["source_revision"])) is None or OID.fullmatch(str(authority["source_tree"])) is None:
        raise ValueError("material authority source identity invalid")
    for field in ("candidate_plan_sha256", "trust_policy_sha256", "evidence_index_sha256", "approval_sha256", "production_plan_sha256"):
        if SHA256.fullmatch(str(authority[field])) is None:
            raise ValueError(f"material authority digest invalid: {field}")

    evidence_path = safe_file(packet, authority["evidence_index"])
    approval_path = safe_file(packet, authority["approval"])
    plan_path = safe_file(packet, authority["production_plan"])
    if digest(evidence_path.read_bytes()) != authority["evidence_index_sha256"]:
        raise ValueError("evidence index file digest mismatch")
    if digest(approval_path.read_bytes()) != authority["approval_sha256"]:
        raise ValueError("approval file digest mismatch")
    if digest(plan_path.read_bytes()) != authority["production_plan_sha256"]:
        raise ValueError("production plan file digest mismatch")

    evidence, approval, plan = load(evidence_path), load(approval_path), load(plan_path)
    evidence_self_sha = self_hash(evidence, "index_sha256")
    approval_self_sha = self_hash(approval, "approval_sha256")
    if evidence.get("contract") != "venatr_build_material_evidence_index_v1":
        raise ValueError("evidence index contract invalid")
    if approval.get("contract") != "venatr_build_material_plan_approval_v1" or approval.get("decision") != "approved":
        raise ValueError("material approval contract or decision invalid")
    for value in (evidence, approval):
        if value.get("source_revision") != authority["source_revision"]:
            raise ValueError("material packet source revision divergence")
        if value.get("source_tree") != authority["source_tree"]:
            raise ValueError("material packet source tree divergence")
        if value.get("candidate_plan_sha256") != authority["candidate_plan_sha256"]:
            raise ValueError("material packet candidate plan divergence")
        if value.get("trust_policy_sha256") != authority["trust_policy_sha256"]:
            raise ValueError("material packet trust policy divergence")
    if approval.get("evidence_index_sha256") != evidence_self_sha:
        raise ValueError("approval does not bind evidence index")
    principals = approval.get("principals") or []
    role_map = {
        str(row.get("role")): str(row.get("identity") or "").strip()
        for row in principals if isinstance(row, dict) and set(row) == {"role", "identity"}
    }
    if set(role_map) != ROLES or any(not value for value in role_map.values()) or len(set(role_map.values())) != 3:
        raise ValueError("material roles are absent or not independent")
    approved_at = datetime.fromisoformat(str(approval.get("approved_at", "")).replace("Z", "+00:00"))
    if approved_at.tzinfo is None or approved_at > now or (now - approved_at.astimezone(timezone.utc)).days > 14:
        raise ValueError("material approval is future-dated or expired")

    rows = evidence.get("materials") or []
    if not isinstance(rows, list) or len(rows) != 9:
        raise ValueError("material evidence index must contain exactly nine materials")
    names: set[str] = set()
    indexed: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"name", "sources"}:
            raise ValueError("material evidence row malformed")
        name, sources = str(row["name"]), row["sources"]
        if not name or name in names or not isinstance(sources, list) or len(sources) != 2:
            raise ValueError("material evidence names or source cardinality invalid")
        names.add(name)
        classes = frozenset(str(source.get("authorityClass")) for source in sources if isinstance(source, dict))
        if classes not in PAIRS:
            raise ValueError(f"material evidence authority pair invalid: {name}")
        for source in sources:
            required_source = {"authority", "authorityClass", "source", "sha256", "method", "receipt", "receiptSha256"}
            if not isinstance(source, dict) or set(source) != required_source or not SHA256.fullmatch(str(source["sha256"])):
                raise ValueError(f"material evidence source invalid: {name}")
            receipt_path = safe_file(packet, source["receipt"])
            if digest(receipt_path.read_bytes()) != source["receiptSha256"]:
                raise ValueError(f"material receipt digest mismatch: {name}")
            receipt = load(receipt_path)
            if (
                receipt.get("contract") != "venatr_build_material_verification_receipt_v1"
                or receipt.get("verified") is not True or receipt.get("revocationStatus") != "good"
                or receipt.get("artifactSha256") != source["sha256"]
                or receipt.get("authority") != source["authority"] or receipt.get("method") != source["method"]
                or receipt.get("sourceRevision") != authority["source_revision"]
                or receipt.get("sourceTree") != authority["source_tree"]
                or receipt.get("candidatePlanSha256") != authority["candidate_plan_sha256"]
                or receipt.get("trustPolicySha256") != authority["trust_policy_sha256"]
            ):
                raise ValueError(f"material receipt semantics invalid: {name}")
        indexed[name] = sources

    metadata = plan.get("metadata") or {}
    materials = (plan.get("spec") or {}).get("materials") or []
    if (
        plan.get("kind") != "ApplianceBuildMaterialAcquisitionPlan"
        or metadata.get("status") != "production-approved"
        or metadata.get("sourceRevision") != authority["source_revision"]
        or metadata.get("sourceTree") != authority["source_tree"]
        or metadata.get("candidatePlanSha256") != authority["candidate_plan_sha256"]
        or metadata.get("trustPolicySha256") != authority["trust_policy_sha256"]
        or metadata.get("evidenceIndexSha256") != evidence_self_sha
        or metadata.get("approvalSha256") != approval_self_sha
        or len(materials) != 9
        or {str(row.get("name")) for row in materials} != names
    ):
        raise ValueError("production material plan authority binding invalid")
    return {
        "contract": "venatr_material_plan_authority_verification_v1",
        "ok": True,
        "candidate_id": authority["candidate_id"],
        "source_revision": authority["source_revision"],
        "material_count": 9,
        "authority_sha256": authority["authority_sha256"],
    }


def verify_root(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    materials = root / "materials"
    if not materials.exists():
        return errors
    for path in sorted(materials.glob("*/authority.json")):
        try:
            verify_packet(path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{path.relative_to(root).as_posix()}:{exc}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority", type=Path)
    args = parser.parse_args()
    try:
        if args.authority:
            result = verify_packet(args.authority)
            print(json.dumps(result, sort_keys=True))
            return 0
        errors = verify_root()
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        errors = [str(exc)]
    print(json.dumps({"ok": not errors, "errors": errors}, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
