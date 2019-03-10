(include "signature")
(include "signature-functor")

(module ecdsa signature-interface
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define load-key load-private-key)
  (define make-verify make-asymmetric-verify))

(module hmac-sha-256 signature-interface
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define load-key load-secret-key)
  (define make-verify make-symmetric-verify))

(module rsa signature-interface
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define load-key load-private-key)
  (define make-verify make-asymmetric-verify))

(module es256 = (signature-functor ecdsa))
(module hs256 = (signature-functor hmac-sha-256))
(module rs256 = (signature-functor rsa))
