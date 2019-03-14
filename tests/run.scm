(include "../urlsafe-base64")
(import chicken.io jwt test urlsafe-base64)

(test-begin "jwt")

(test-group "urlsafe-base64"
  (test "removes padding"
        "TGV0IHVzIHRyeSB0byB0ZWFjaCBnZW5lcm9zaXR5IGFuZCBhbHRydWlzbSwgYmVjYXVzZSB3ZSBhcmUgYm9ybiBzZWxmaXNoLg"
        (urlsafe-base64-encode
          "Let us try to teach generosity and altruism, because we are born selfish."))
  (test "substitutes unsafe characters"
        "BgYGQkJCAQIDBN6tvu__"
        (urlsafe-base64-encode
          "\x06\x06\x06\x42\x42\x42\x01\x02\x03\x04\xDE\xAD\xBE\xEF\xFF"))
  (test "invertible"
        "The genes are master programmers, and they are programming for their lives."
        (urlsafe-base64-decode
          (urlsafe-base64-encode
            "The genes are master programmers, and they are programming for their lives."))))

(test-group "codecs"
  (test "hs256"
        '()
        (jwt-decode (jwt-encode '() "secret") "secret"))

  (test "rs256"
        '()
        (jwt-decode
          (jwt-encode '() (read-string #f (open-input-file "rsa-private.pem")))
          (read-string #f (open-input-file "rsa-private.pem"))))

  ; XXX Does this actually work? jwt.io says `no`
  (test "es256"
        '()
        (jwt-decode
          (jwt-encode '() (read-string #f (open-input-file "ecdsa-private.pem")))
          (read-string #f (open-input-file "ecdsa-private.pem"))))

  (test-error
    "decode unexpected algorithm"
    (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ" "secret" "RS256"))

  (test-error
    "decode invalid signature"
    (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ" "foo" "HS256")))

(test-end "jwt")
(test-exit)
