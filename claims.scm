; claim-spec            := <atom-spec> | <atom-or-member-spec> | <time-spec>
; atom-spec             := ('iss | 'jti | 'sub . <atom>)
; atom-or-member-spec   := ('aud . <atom> | (<atom> ...))
; time-spec             := ('exp | 'nbf . [<leeway>])
(module claims (validate-claims)
  (import (chicken base) (chicken time) scheme)

  (define (claim-error claim actual expected)
    (error "Invalid claim" claim actual expected))

  (define (validate-claim name claim spec)
    (case name
      ((iss jti sub) (or (equal? claim spec)
                          (claim-error name claim spec)))
      ((aud) (or (if (list? spec) (member claim spec) (equal? claim spec))
                  (claim-error name claim spec)))
      ((exp) (or (< (current-seconds) (+ claim (if (null? spec) 0 spec)))
                  (claim-error name claim spec)))
      ((nbf) (or (> (current-seconds) (- claim (if (null? spec) 0 spec)))
                  (claim-error name claim spec)))
      (else (error "Unknown claim" name))))

  (define (validate-claims claims claims-spec)
    (for-each (lambda (claim-spec)
                (let* ((name (car claim-spec))
                       (claim (cdr (assoc name claims)))
                       (spec (cdr claim-spec)))
                  (validate-claim name claim spec)))
              claims-spec)))
