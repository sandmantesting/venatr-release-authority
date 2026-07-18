#!/usr/bin/env python3
"""Create generation zero from an already validated P0-P7 candidate request."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

from verify_authority import canonical, digest, load, request_blockers

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workflow-repository", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    args = parser.parse_args()
    request = load(args.request)
    policy = load(ROOT / "authority/policy.json")
    blockers = request_blockers(request, policy)
    if request.get("generation") != 0:
        blockers.append("GENESIS_GENERATION_MUST_BE_ZERO")
    if args.workflow_repository != policy.get("authority_repository"):
        blockers.append("WORKFLOW_REPOSITORY_INVALID")
    if not args.workflow_ref.endswith("/.github/workflows/bootstrap-generation-zero.yml@refs/heads/main"):
        blockers.append("WORKFLOW_REF_INVALID")
    if len(args.workflow_sha) != 40 or any(ch not in "0123456789abcdef" for ch in args.workflow_sha):
        blockers.append("WORKFLOW_SHA_INVALID")
    if blockers:
        print(json.dumps({"status": "blocked", "blockers": sorted(set(blockers))}, sort_keys=True))
        return 1
    state: dict[str, Any] = {
        "contract": "venatr_release_authority_state_v1",
        "generation": 0,
        "candidate_id": request["candidate_id"],
        "source_repository": request["source_repository"],
        "source_revision": request["source_revision"],
        "source_tree": request["source_tree"],
        "source_archive_sha256": request["source_archive_sha256"],
        "candidate_request_sha256": request["request_sha256"],
        "previous_authority_state_sha256": None,
        "issued_at": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
        "workflow": {
            "repository": args.workflow_repository, "ref": args.workflow_ref,
            "sha": args.workflow_sha, "run_id": args.run_id, "run_attempt": args.run_attempt,
        },
    }
    state["state_sha256"] = digest(canonical(state))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "state_sha256": state["state_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

