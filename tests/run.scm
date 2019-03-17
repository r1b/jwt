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
          (jwt-encode '() (read-string #f (open-input-file "rsa-private.pem")) "RS256")
          (read-string #f (open-input-file "rsa-public.pub")) "RS256"))

  (test "es256"
        '()
        (jwt-decode
          (jwt-encode '() (read-string #f (open-input-file "ecdsa-private.pem")) "ES256")
          (read-string #f (open-input-file "ecdsa-public.pub")) "ES256"))

  (test "none"
        '()
        (jwt-decode (jwt-encode '() "" "none") "" "none" #f)))

(test-group "token-verification"
  (test-error "verify none"
              (jwt-decode (jwt-encode '() "" "none") "" "none"))
  (test-error
    "decode unexpected algorithm"
    (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ" "secret" "RS256"))

  (test-error
    "decode invalid signature"
    (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ" "foo" "HS256")))

(test-group "claim-verification"
  (test "verify iss (valid)"
        '((iss . "https://nsa.gov"))
        (jwt-decode
          (jwt-encode '((iss . "https://nsa.gov")) "secret" "HS256")
          "secret"
          "HS256"
          #t
          '((iss . "https://nsa.gov"))))

  (test-error "verify iss (invalid)"
              (jwt-decode
                (jwt-encode '((iss . "https://cia.gov")) "secret" "HS256")
                "secret"
                "HS256"
                #t
                '((iss . "https://nsa.gov"))))

  (test "verify jti (valid)"
        '((jti . "E1B5296E-BDA6-41FB-A69B-F719B04F7826"))
        (jwt-decode
          (jwt-encode '((jti . "E1B5296E-BDA6-41FB-A69B-F719B04F7826")) "secret" "HS256")
          "secret"
          "HS256"
          #t
          '((jti . "E1B5296E-BDA6-41FB-A69B-F719B04F7826"))))

  (test-error "verify jti (invalid)"
              (jwt-decode
                (jwt-encode '((jti . "E1B5296E-BDA6-41FB-A69B-F719B04F7826")) "secret" "HS256")
                "secret"
                "HS256"
                #t
                '((jti . "BFC2F372-F893-410D-9EBE-2BE5F053678C"))))
  (test "verify sub (valid)"
        '((sub . "user:12345"))
        (jwt-decode
          (jwt-encode '((sub . "user:12345")) "secret" "HS256")
          "secret"
          "HS256"
          #t
          '((sub . "user:12345"))))

  (test-error "verify sub (invalid)"
        (jwt-decode
          (jwt-encode '((sub . "user:12345")) "secret" "HS256")
          "secret"
          "HS256"
          #t
          '((sub . "user:54321")))))

(test-end "jwt")
(test-exit)
