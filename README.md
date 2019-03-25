# jwt

RFC7519 - JSON Web Token (JWT)

## warning

You *probably* shouldn't use this.

## roadmap

### v1

#### 3E
* [ ] Add JWK support
    * [ ] Interface
    * [ ] Support symmetric keys
    * [ ] ASN.1 codecs
        * [ ] SubjectPublicKeyInfo
        * [ ] PrivateKeyInfo
        * [ ] RSAPublicKey
        * [ ] RSAPrivateKey
        * [ ] ECPrivateKey
    * [ ] JWK <-> ASN.1 <-> PEM
* [ ] https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
    * [ ] Overhaul the interface for loading keys to enforce PKEY type

#### 2E
* [x] Add claim validation
    * [x] Add tests with non-empty claims
* [ ] Handle all edge cases in high-level interface
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
* [ ] Improve tests, use https://tools.ietf.org/html/draft-ietf-jose-cookbook-08

#### 1E
* [ ] Explicitly handle ASCII / UTF-8 conversions
* [x] Add tests for none, RS256, ES256
* [x] Handle all foreign errors in signatures
* [ ] Fix memory leaks w PKEY, MD_CTX
* [x] Fix ugly branching in sign / verify high-level interface


### v2

* [ ] Support ports as message / key source
* [ ] Nested JWTs
* [ ] Encrypted JWTs
* [ ] Pull out useful eggs:
    * [ ] constant-time-equal
    * [ ] libcrypto (start from signatures)
    * [ ] asn-1 (start from JWK codecs)
    * [ ] port srfi-60, srfi-151 to chicken 5
