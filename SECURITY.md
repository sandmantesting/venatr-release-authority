# Security boundary

Public and expected: verifier code, schemas, policies, public keys, opaque candidate
identifiers, Git object identifiers, SHA-256 digests, qualification cell identifiers,
signed attestations, and monotonic release state.

Forbidden: Venatr source, source archives, appliance or image bytes, credentials,
private keys, tokens, customer information, raw logs, vulnerability evidence, license
material, model weights, proprietary SBOM component detail, and unredacted build paths.

If forbidden material is committed, stop promotion, rotate affected credentials, revoke
the affected authority generation, and preserve the incident record outside this public
repository.

