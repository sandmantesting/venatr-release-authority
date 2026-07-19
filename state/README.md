# Monotonic authority state

This directory contains keyless Sigstore-attested, append-only release authority
generations and their offline bundles. Generation zero is created exactly once by the
protected bootstrap workflow. Later generations must name and hash their immediate
predecessor.
