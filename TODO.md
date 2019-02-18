# todo

* Implement JWS
    * Need a urlsafe base64 - emailed last known author
* Support HS256 and "none"
* Be more defensive against weird JWTs
* Support validation of claims
* Explicitly force ASCII / UTF-8 handling where applicable

# long-term todo
* Support RS256 + JWKs
    * Need an RSA impl..
        * Chicken 4 has cryptlib but I would rather use openssl + libcrypto

# bored todo

* Implement JWE
* Implement ES256
* Implement nested JWTs

# references

* [JWA](https://tools.ietf.org/html/rfc7518)
* [JWK](https://tools.ietf.org/html/rfc7517)
* [JWS](https://tools.ietf.org/html/rfc7515)
* [JWT](https://tools.ietf.org/html/rfc7519)
