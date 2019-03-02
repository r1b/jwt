(include "signature")
(include "signature-functor")

(module ecdsa signature-interface
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define (load-key key) (load-pem-private-key key))
  (define (verify-signature message key signature)
    (verify-asymmetric message key signature)))

(module hmac-sha-256 signature-interface
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define (load-key key) (load-raw-private-key key))
  (define (verify-signature message key signature)
    (verify-symmetric message key signature)))

(module rsa signature-interface
  (import scheme signature)
  (define (get-message-digest) (get-message-digest-by-name "sha256"))
  (define (load-key key) (load-pem-private-key key))
  (define (verify-signature message key signature)
    (verify-asymmetric message key signature)))

(module es256 = (signature-functor ecdsa))
(module hs256 = (signature-functor hmac-sha-256))
(module rs256 = (signature-functor rsa))
