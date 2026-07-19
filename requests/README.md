# Candidate requests

Each JSON document in this directory is a reviewed, digest-only request conforming to
`schemas/release-candidate-request-v1.schema.json`. Proprietary payloads, credentials,
logs, and raw qualification evidence are forbidden here.

The request must bind the exact release-set digest, complete evidence-root index,
source/archive identity, material snapshot, P0-P7 phase manifests, and the
candidate-bound role and independent-environment assignment documents. A set of
phase hashes without those root and separation bindings is inadmissible.
