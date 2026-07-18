# Monotonic authority state

This directory contains KMS-signed, append-only release authority generations. Generation
zero is created exactly once by the protected bootstrap workflow. Later generations must
name and hash their immediate predecessor.

