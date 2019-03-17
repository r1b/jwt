(include "signature")
(include "signature-functor")

(module ES256 = signature-functor
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define load-key load-private-key)
  (define make-verify make-asymmetric-verify))

(module HS256 = signature-functor
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define load-key load-secret-key)
  (define make-verify make-symmetric-verify))

(module RS256 = signature-functor
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define load-key load-private-key)
  (define make-verify make-asymmetric-verify))
