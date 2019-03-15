# jwt

RFC7519 - JSON Web Token (JWT)

## warning

You *probably* shouldn't use this.

## roadmap

* [x] Add tests for none, RS256, ES256
* [ ] Add claim validation
* [ ] Explicitly handle ASCII / UTF-8 conversions
* [ ] Handle all edge cases in high-level interface
* [ ] Add tests with non-empty claims
* [ ] https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
    * [ ] Overhaul the interface for loading keys to enforce PKEY type
* [ ] Fix ugly branching in sign / verify high-level interface
* [ ] Pull out constant-time-equal, signatures into their own eggs
* [ ] Support ports as message / key source
* [ ] Handle errors in `EVP_DigestVerify*`
* [ ] Improve tests, use https://tools.ietf.org/html/draft-ietf-jose-cookbook-08
