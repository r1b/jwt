# jwt

RFC7519 - JSON Web Token (JWT)

## warning

You *probably* shouldn't use this.

## roadmap

* [x] Add tests for none, RS256, ES256
* [x] Handle all foreign errors in signatures
* [ ] Add claim validation
* [ ] Explicitly handle ASCII / UTF-8 conversions
* [ ] Handle all edge cases in high-level interface
* [ ] Add tests with non-empty claims
* [ ] Add JWK support
* [ ] https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
    * [ ] Overhaul the interface for loading keys to enforce PKEY type
* [ ] Fix ugly branching in sign / verify high-level interface
* [ ] Pull out constant-time-equal, signatures into their own eggs
* [ ] Support ports as message / key source
* [ ] Improve tests, use https://tools.ietf.org/html/draft-ietf-jose-cookbook-08
* [ ] Add a macro for foreign-error
* [ ] Fix memory leaks w PKEY, MD_CTX
