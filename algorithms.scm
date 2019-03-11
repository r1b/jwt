(include "signature")
(include "signature-functor")

(module es256 = signature-functor
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define load-key load-private-key)
  (define make-verify make-asymmetric-verify))

(module hs256 = signature-functor
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define load-key load-secret-key)
  (define make-verify make-symmetric-verify))

(module rs256 = signature-functor
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define load-key load-private-key)
  (define make-verify make-asymmetric-verify))
