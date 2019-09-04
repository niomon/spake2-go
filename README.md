# spake2-go
The SPAKE2 password-authenticated key-exchange algorithm, in Go.

This implementation focus on following [`draft-irtf-cfrg-spake2-08`](standard-url) with SPAKE2, SPAKE2+ and key confirmation.

This have not go through a formal cryptographic audit and should be awared in any use case.

Also this do not protect against time attacks as operations are probably not constant-time.