from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.verify_material_authority import canonical, digest, verify_packet


SOURCE = "a" * 40
TREE = "b" * 40
CANDIDATE_SHA = "sha256:" + "c" * 64
TRUST_SHA = "sha256:" + "d" * 64


def write(path: Path, value: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return digest(path.read_bytes())


def packet(root: Path) -> Path:
    now = datetime.now(timezone.utc).isoformat()
    material_rows = []
    plan_rows = []
    for index in range(9):
        name = f"material-{index}"
        artifact_sha = "sha256:" + str(index + 1) * 64
        sources = []
        plan_sources = []
        for suffix, authority, authority_class, method in (
            ("upstream", f"upstream:{name}", "upstream-signing-authority", "upstream-signature"),
            ("controlled", "venatr-controlled-reproducer", "controlled-reproducer", "cosign"),
        ):
            receipt = {
                "contract": "venatr_build_material_verification_receipt_v1",
                "verified": True,
                "revocationStatus": "good",
                "artifactSha256": artifact_sha,
                "authority": authority,
                "method": method,
                "sourceRevision": SOURCE,
                "sourceTree": TREE,
                "candidatePlanSha256": CANDIDATE_SHA,
                "trustPolicySha256": TRUST_SHA,
            }
            relative = f"evidence/{name}.{suffix}.json"
            receipt_sha = write(root / relative, receipt)
            source = {
                "authority": authority,
                "authorityClass": authority_class,
                "source": f"https://evidence.example/{name}/{suffix}",
                "sha256": artifact_sha,
                "method": method,
                "receipt": relative,
                "receiptSha256": receipt_sha,
            }
            sources.append(source)
            plan_sources.append({
                "authority": authority,
                "authorityClass": authority_class,
                "source": source["source"],
                "sha256": artifact_sha,
                "evidence": {"path": relative, "sha256": receipt_sha, "method": method, "verified": True},
            })
        material_rows.append({"name": name, "sources": sources})
        plan_rows.append({"name": name, "verification": {"independentDigestSources": plan_sources}})
    evidence = {
        "contract": "venatr_build_material_evidence_index_v1",
        "source_revision": SOURCE,
        "source_tree": TREE,
        "candidate_plan_sha256": CANDIDATE_SHA,
        "trust_policy_sha256": TRUST_SHA,
        "materials": material_rows,
    }
    evidence["index_sha256"] = digest(canonical(evidence))
    evidence_file_sha = write(root / "evidence-index.json", evidence)
    approval = {
        "contract": "venatr_build_material_plan_approval_v1",
        "decision": "approved",
        "approved_at": now,
        "policy": "venatr-appliance-production-material-trust",
        "source_revision": SOURCE,
        "source_tree": TREE,
        "candidate_plan_sha256": CANDIDATE_SHA,
        "trust_policy_sha256": TRUST_SHA,
        "evidence_index_sha256": evidence["index_sha256"],
        "principals": [
            {"role": "material-acquirer", "identity": "sigstore:workflow"},
            {"role": "supply-chain-reviewer", "identity": "codex:reviewer"},
            {"role": "release-approver", "identity": "authority:protected-main"},
        ],
    }
    approval["approval_sha256"] = digest(canonical(approval))
    approval_file_sha = write(root / "approval.json", approval)
    plan = {
        "apiVersion": "release.venatr.dev/v1",
        "kind": "ApplianceBuildMaterialAcquisitionPlan",
        "metadata": {
            "status": "production-approved",
            "sourceRevision": SOURCE,
            "sourceTree": TREE,
            "candidatePlanSha256": CANDIDATE_SHA,
            "trustPolicySha256": TRUST_SHA,
            "evidenceIndexSha256": evidence["index_sha256"],
            "approvalSha256": approval["approval_sha256"],
        },
        "spec": {"materials": plan_rows},
    }
    plan_sha = write(root / "production-plan.json", plan)
    authority = {
        "contract": "venatr_material_plan_authority_v1",
        "candidate_id": "venatr-aaaaaaaaaaaa-cccccccccccc",
        "source_revision": SOURCE,
        "source_tree": TREE,
        "candidate_plan_sha256": CANDIDATE_SHA,
        "trust_policy_sha256": TRUST_SHA,
        "evidence_index": "evidence-index.json",
        "evidence_index_sha256": evidence_file_sha,
        "approval": "approval.json",
        "approval_sha256": approval_file_sha,
        "production_plan": "production-plan.json",
        "production_plan_sha256": plan_sha,
    }
    authority["authority_sha256"] = digest(canonical(authority))
    write(root / "authority.json", authority)
    return root / "authority.json"


class MaterialAuthorityTests(unittest.TestCase):
    def test_complete_digest_only_packet_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = verify_packet(packet(Path(temporary)))
            self.assertTrue(result["ok"])
            self.assertEqual(result["material_count"], 9)

    def test_aliasing_or_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority_path = packet(root)
            approval_path = root / "approval.json"
            approval = json.loads(approval_path.read_text(encoding="utf-8"))
            approval["principals"][1]["identity"] = approval["principals"][0]["identity"]
            approval.pop("approval_sha256")
            approval["approval_sha256"] = digest(canonical(approval))
            write(approval_path, approval)
            with self.assertRaisesRegex(ValueError, "approval file digest mismatch"):
                verify_packet(authority_path)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority_path = packet(root)
            receipt = next((root / "evidence").glob("*.json"))
            receipt.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "receipt digest mismatch"):
                verify_packet(authority_path)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority_path = packet(root)
            evidence_path = root / "evidence-index.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["source_tree"] = "e" * 40
            evidence.pop("index_sha256")
            evidence["index_sha256"] = digest(canonical(evidence))
            authority = json.loads(authority_path.read_text(encoding="utf-8"))
            authority["evidence_index_sha256"] = write(evidence_path, evidence)
            authority.pop("authority_sha256")
            authority["authority_sha256"] = digest(canonical(authority))
            write(authority_path, authority)
            with self.assertRaisesRegex(ValueError, "source tree divergence"):
                verify_packet(authority_path)


if __name__ == "__main__":
    unittest.main()
