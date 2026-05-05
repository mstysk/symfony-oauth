# Test fixtures — RSA keypair

`private.key` and `public.key` are committed RSA keys used **only** by
the unit/functional test suite. They MUST NOT be used to sign real
tokens; production keys live under `config/jwt/` and are gitignored.

If you regenerate these, run any test once afterwards and update any
hard-coded `kid` expectations.
