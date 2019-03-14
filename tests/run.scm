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
  (test "encode empty hmac payload"
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ"
        (jwt-encode '() "secret"))

  (test "decode empty hmac payload"
        '()
        (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ" "secret"))

  (test "encode empty rsa payload"
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.e30.D_jZijCIsgJE_hd_HnF8-3If11ExB0RTVgVGaNetM1CSSDtMG47j_O6r2q9J2WoQ1hCuPzF_v2N9YmmCmTKQw1xxU_rphFYOs9SIyp-80CX4FinzZYamgsuRKsHo4AecRduicQn4oX-sHfLjuD56ZBUvc2K5Y4t4f0Lp4mj02i9Qip-xvQzLKEd43Wnkl84eX_y_JrqxNCjX8vcV8Wlj2PQm9h0BDtwuKdFEaR5fpKOnD4oBMs56g7QhRGEc9U-UDPWqeDAWAdMht6u_vjvKQQZ6gvVGpnZQt-S6vOMwz2J1Q1HMWqJBu07ShDByIDpxPAaKhkf0v6ZoPtigDY1ioQ"
        (jwt-encode '() (read-string #f (open-input-file "rsa-private.pem")) "RS256"))


  (test "decode empty rsa payload"
        '()
        (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.e30.D_jZijCIsgJE_hd_HnF8-3If11ExB0RTVgVGaNetM1CSSDtMG47j_O6r2q9J2WoQ1hCuPzF_v2N9YmmCmTKQw1xxU_rphFYOs9SIyp-80CX4FinzZYamgsuRKsHo4AecRduicQn4oX-sHfLjuD56ZBUvc2K5Y4t4f0Lp4mj02i9Qip-xvQzLKEd43Wnkl84eX_y_JrqxNCjX8vcV8Wlj2PQm9h0BDtwuKdFEaR5fpKOnD4oBMs56g7QhRGEc9U-UDPWqeDAWAdMht6u_vjvKQQZ6gvVGpnZQt-S6vOMwz2J1Q1HMWqJBu07ShDByIDpxPAaKhkf0v6ZoPtigDY1ioQ" (read-string #f (open-input-file "rsa-public.pub")) "RS256"))

  ; XXX DSA is not stable - how to test encode?

  ; XXX This seems to work but jwt.io is not convinced?

  (test "decode empty ecdsa payload"
        '()
        (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.e30.MEYCIQChJplQ9YwNBkjRU-EbkcoQlun1_JeusIKqRUrbQuA3aQIhAKrHC55RJNd44dH_I0HCs9iIkv4kfTqhnHbssU8_NElQ" (read-string #f (open-input-file "ecdsa-public.pub")) "ES256"))

  (test-error
    "decode unexpected algorithm"
    (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ" "secret" "RS256"))

  (test-error
    "decode invalid signature"
    (jwt-decode "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.e30.DMCAvRgzrcf5w0Z879BsqzcrnDFKBY_GN6c3qKOUFtQ" "foo" "HS256")))

(test-end "jwt")
(test-exit)
