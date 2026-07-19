# Material-plan authority

Each candidate directory contains only digest-bound public metadata:

- `authority.json` — self-hashed packet index;
- `evidence-index.json` — exactly two independent authorities for each of nine materials;
- `approval.json` — source-bound approval by three distinct accountable principals;
- `production-plan.json` — the generated, production-approved acquisition plan;
- `evidence/*.json` — verification receipts and public signature bundles only.

Private source, acquired artifacts, credentials, model weights, and proprietary build paths are forbidden.
Every packet binds the exact source commit, source tree, candidate-plan digest, and
material-trust-policy digest through its index, approval, receipts, and production
plan. It must pass `scripts/verify_material_authority.py`, Authority CI, and
independent protected-main review.
