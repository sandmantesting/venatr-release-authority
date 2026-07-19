# Venatr Release Authority

This public repository is Venatr's production release trust anchor. It contains no
Venatr implementation source, private artifacts, credentials, customer data, or
decryption material.

The private source repository is identified only by repository identity, immutable
Git commit and tree OIDs, a deterministic source-archive SHA-256 digest, and signed
qualification evidence digests. A protected workflow may create generation zero only
after fresh P0–P7 evidence is supplied. The protected workflow uses GitHub OIDC and
the Sigstore Public Good instance to issue a short-lived signing certificate, records
the attestation in Rekor, and persists the complete offline-verifiable bundle.

Production rules:

- `main` and `venatr-*` tags are protected.
- Direct pushes, force pushes, deletion, administrator bypass and self-approval are forbidden.
- `Verify public authority` is required.
- Candidate requests carry hashes, never private source or artifacts.
- Generation zero has no predecessor. Every later state must name and hash its predecessor.
- No persistent private signing key exists. Ephemeral signing material and credentials
  are never GitHub secrets or repository files.

See [SECURITY.md](SECURITY.md) for the disclosure boundary.
