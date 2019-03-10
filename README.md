# jwt

RFC7519 - JSON Web Token (JWT)

## warning

You *probably* shouldn't use this.

## roadmap

[ ] Add tests for none, RS256, ES256
[ ] Add tests with non-empty claims
[ ] Explicitly handle ASCII / UTF-8 conversions
[ ] Overhaul the interface for loading keys to enforce PKEY type
[ ] Add claim validation
[ ] Handle all edge cases in high-level interface
[ ] Fix ugly branching in sign / verify high-level interface
[ ] Pull out constant-time-equal, signatures into their own eggs
