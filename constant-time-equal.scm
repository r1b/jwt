; Compare secrets in O(1)
; https://codahale.com/a-lesson-in-timing-attacks/
; https://github.com/jpadilla/pyjwt/blob/1.7.1/jwt/compat.py#L33-L47
(module constant-time-equal (constant-time-equal?)
  (import chicken.bitwise srfi-1 scheme)
  (define (constant-time-equal? s1 s2)
    (if (not (= (string-length s1) (string-length s2)))
        #f
        (= (fold bitwise-ior
                 0
                 (map (lambda (pair) (bitwise-xor (first pair) (second pair)))
                      (zip (map char->integer (string->list s1))
                           (map char->integer (string->list s2)))))
           0))))

