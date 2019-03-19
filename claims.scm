; claim-spec            := <atom-spec> | <atom-or-member-spec> | <time-spec>
; atom-spec             := ('iss | 'jti | 'sub . <atom>)
; atom-or-list-spec   := ('aud . <atom> | (<atom> ...))
; time-spec             := ('exp | 'nbf . [<leeway>])
(module claims (validate-claims)
  (import (chicken base) (chicken time) scheme srfi-133)

  ; ---------------------------------------------------------------------------

  (define (claim-error claim actual expected)
    (error "Invalid claim" claim actual expected))

  (define (type-error claim expected-type)
    (error "Invalid claim type" claim expected-type))

  ; ---------------------------------------------------------------------------

  (define (ensure-string-or-uri value)
    (string? value))

  (define (ensure-vector-of-string-or-uri value)
    (and (vector? value) (vector-every ensure-sting-or-uri value)))

  (define (ensure-timestamp value)
    (integer? value))

  ; ---------------------------------------------------------------------------

  (define (vector-subset src dest)
    (vector-every (lambda (src-element)
                    (vector-any (lambda (dest-element)
                                  (equal? src-element dest-element))
                                dest))
                  src))

  ; ---------------------------------------------------------------------------

  (define (validate-claim name claim spec)
    (case name
      ((iss jti sub) (begin (or (ensure-string-or-uri claim) (type-error name "string"))
                            (or (equal? claim spec) (claim-error name claim spec))))
      ((aud) (begin (or (ensure-string-or-uri claim)
                        (ensure-vector-of-string-or-uri claim)
                        (type-error name "string or vector"))
                    (let ((claim (if (string? claim) (vector claim) claim))
                          (spec ((if (string? spec) (vector spec) spec))))
                      (or (vector-subset claim spec)
                          (claim-error name claim spec)))))
      ((exp) (begin (or (ensure-timestamp claim) (type-error name "integer"))
                    (or (< (current-seconds) (+ claim (if (null? spec) 0 spec)))
                        (claim-error name claim spec))))
      ((nbf) (begin (or (ensure-timestamp claim) (type-error name "integer"))
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
