# Test App key

A throwaway RSA keypair, generated for this repository's tests and used nowhere
else. It is not the key of any GitHub App, real or otherwise, and it never
authenticates against anything — the only tests that use it either verify a
signature locally or talk to a stub listener on localhost.

Three files, one key:

- `test-app-key.pem` — PKCS#8 private key
- `test-app-key.pkcs1.pem` — the same key in PKCS#1, the form GitHub hands out
- `test-app-key.pub.pem` — the public key, for verifying what HQ signed

A secret scanner will flag these, correctly: they are private keys committed to
a repository. That is the expected outcome, and the Finding is a Dismiss.
