(include "../constant-time-equal.scm")
(import constant-time-equal test)

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

(test-end "jwt")
(test-exit)
