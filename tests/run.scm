(include "../constant-time-equal.scm")
(include "../urlsafe-base64.scm")
(import constant-time-equal jwt test urlsafe-base64)

(test-begin "jwt")

(test-group "constant-time-equal"
  (test
    "equal length, equal"
    #t
    (constant-time-equal?
      "abcdefghijklmnopqrstuvwxyz"
      "abcdefghijklmnopqrstuvwxyz"))
  (test
    "equal length, not equal"
    #f
    (constant-time-equal?
      "abcdefghijklmnopqrstuvwxyz"
      "abcdefghijklmnopqrstuvwxyZ"))

  (test
    "not equal length, not equal"
    #f
    (constant-time-equal?
      "abcdefghijklmnopqrstuvwxyz"
      "abcdefghijk")))

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
  (test "encode empty payload"
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ"
        (jwt-encode '() "secret"))

  (test "decode empty payload"
        '()
        (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ" "secret" "HS256"))

  (test-error
    "decode unexpected algorithm"
    (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ" "secret" "RS256"))

  (test-error
    "decode invalid signature"
    (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ" "foo" "RS256")))

(test-end "jwt")
(test-exit)
