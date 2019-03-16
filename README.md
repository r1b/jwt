# jwt

RFC7519 - JSON Web Token (JWT)

## warning

You *probably* shouldn't use this.

## roadmap

### v1

* [x] Add tests for none, RS256, ES256
* [x] Handle all foreign errors in signatures
* [ ] Add claim validation
    * [ ] Add tests with non-empty claims
* [ ] Explicitly handle ASCII / UTF-8 conversions
* [ ] Handle all edge cases in high-level interface
* [ ] Add JWK support
* [ ] Support the full set of algos on jwt.io
    * [ ] HS384
    * [ ] HS512
    * [ ] RS384
    * [ ] RS512
    * [ ] ES384
    * [ ] ES512
    * [ ] PS256
    * [ ] PS384
    * [ ] PS512
* [ ] https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
    * [ ] Overhaul the interface for loading keys to enforce PKEY type
* [ ] Fix memory leaks w PKEY, MD_CTX
* [ ] Support ports as message / key source
* [ ] Improve tests, use https://tools.ietf.org/html/draft-ietf-jose-cookbook-08
* [ ] Fix ugly branching in sign / verify high-level interface
* [ ] Pull out constant-time-equal, signatures into their own eggs
* [ ] Add a macro for foreign-error

### v2

* [ ] Nested JWTs
* [ ] Encrypted JWTs
