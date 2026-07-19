from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from scripts.verify_authority import (
    ROOT,
    action_pin_blockers,
    canonical,
    digest,
    hygiene_blockers,
    load,
    policy_blockers,
    request_blockers,
    qualification_workflow_blockers,
    workflow_blockers,
)


POLICY = {
    "source_repository": "sandmantesting/Venatr",
}


def request() -> dict:
    value = {
        "contract": "venatr_release_candidate_request_v1",
        "candidate_id": "venatr-" + "a" * 12 + "-" + "c" * 12,
        "generation": 0,
        "source_repository": "sandmantesting/Venatr",
        "source_revision": "a" * 40,
        "source_tree": "b" * 40,
        "source_archive_sha256": "sha256:" + "c" * 64,
        "release_definition_sha256": "sha256:" + "d" * 64,
        "material_snapshot_sha256": "sha256:" + "e" * 64,
        "qualification_evidence": {
            f"P{number}": {"manifest_sha256": "sha256:" + str(number) * 64, "status": "passed"}
            for number in range(8)
        },
        "previous_authority_state_sha256": None,
    }
    value["request_sha256"] = digest(canonical(value))
    return value


class AuthorityVerifierTests(unittest.TestCase):
    def test_keyless_signing_policy_is_exact(self) -> None:
        self.assertEqual(policy_blockers(load(ROOT / "authority/policy.json")), [])

    def test_signing_policy_drift_blocks(self) -> None:
        policy = load(ROOT / "authority/policy.json")
        policy["signing"]["certificate_identity"] = "untrusted"
        self.assertIn("SIGNING_AUTHORITY_POLICY_INVALID", policy_blockers(policy))

    def test_keyless_bootstrap_workflow_is_closed(self) -> None:
        self.assertEqual(workflow_blockers(ROOT), [])

    def test_keyless_qualification_workflow_is_closed(self) -> None:
        self.assertEqual(qualification_workflow_blockers(ROOT), [])

    def test_every_action_is_commit_pinned(self) -> None:
        self.assertEqual(action_pin_blockers(ROOT), [])

    def test_generation_zero_request_is_closed(self) -> None:
        self.assertEqual(request_blockers(request(), POLICY), [])

    def test_request_hash_and_phase_failure_block(self) -> None:
        value = request()
        value["qualification_evidence"]["P7"]["status"] = "pending"
        blockers = request_blockers(value, POLICY)
        self.assertIn("REQUEST_HASH_INVALID", blockers)
        self.assertIn("QUALIFICATION_EVIDENCE_INVALID:P7", blockers)

    def test_non_genesis_requires_predecessor(self) -> None:
        value = request()
        value["generation"] = 1
        material = copy.deepcopy(value)
        material.pop("request_sha256")
        value["request_sha256"] = digest(canonical(material))
        self.assertIn("PREDECESSOR_REQUIRED", request_blockers(value, POLICY))

    def test_hygiene_rejects_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = "-----BEGIN " + "PRIVATE KEY-----\nforbidden\n"
            (root / "secret.pem").write_text(marker, encoding="utf-8")
            blockers = hygiene_blockers(root)
        self.assertIn("PUBLIC_FILE_TYPE_FORBIDDEN:secret.pem", blockers)
        self.assertIn("PUBLIC_SECRET_PATTERN:secret.pem", blockers)


if __name__ == "__main__":
    unittest.main()
