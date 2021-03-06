; claim-spec            := <atom-spec> | <atom-or-member-spec> | <time-spec>
; atom-spec             := ('iss | 'jti | 'sub . <atom>)
; atom-or-vector-spec   := ('aud . <atom> | #(<atom> ...))
; time-spec             := ('exp | 'nbf . [<leeway>])
(module claims (validate-claims)
  (import (chicken base) (chicken time) scheme srfi-133)

  ; ---------------------------------------------------------------------------

  (define (claim-error claim actual expected)
    (error "Invalid claim" claim actual expected))

  (define (type-error claim expected-type)
    (error "Invalid claim type" claim expected-type))

  ; ---------------------------------------------------------------------------

  (define (string-or-uri? value)
    (string? value))

  (define (vector-of-string-or-uri? value)
    (and (vector? value) (vector-every string-or-uri? value)))

  (define (timestamp? value)
    (integer? value))

  ; ---------------------------------------------------------------------------

  (define (vector-subset? src dest)
    (vector-every (lambda (src-element)
                    (vector-any (lambda (dest-element)
                                  (equal? src-element dest-element))
                                dest))
                  src))

  ; ---------------------------------------------------------------------------

  (define (validate-claim name claim spec)
    (case name
      ((iss jti sub) (begin (or (string-or-uri? claim) (type-error name "string"))
                            (or (equal? claim spec) (claim-error name claim spec))))
      ((aud) (begin (or (string-or-uri? claim)
                        (vector-of-string-or-uri? claim)
                        (type-error name "string or vector"))
                    (let ((claim (if (string? claim) (vector claim) claim))
                          (spec (if (string? spec) (vector spec) spec)))
                      (or (vector-subset? claim spec)
                          (claim-error name claim spec)))))
      ((exp) (begin (or (timestamp? claim) (type-error name "integer"))
                    (or (< (current-seconds) (+ claim (if (null? spec) 0 spec)))
                        (claim-error name claim spec))))
      ((nbf) (begin (or (timestamp? claim) (type-error name "integer"))
                    (or (> (current-seconds) (- claim (if (null? spec) 0 spec)))
                        (claim-error name claim spec))))
      (else (error "Unknown claim" name))))

  (define (validate-claims claims claims-spec)
    (for-each (lambda (claim-spec)
                (let* ((name (car claim-spec))
                       (spec (cdr claim-spec))
                       (claim (cdr (or (assoc name claims) (claim-error name #f spec)))))
                  (validate-claim name claim spec)))
              claims-spec)))
