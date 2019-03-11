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

; FIXME I still feel like I'm doing this wrong..
; If this isn't wrong, maybe use a macro?

(module algorithms (sign-es256 sign-hs256 sign-rs256 verify-es256 verify-hs256 verify-rs256)
  (import scheme)
  (define (sign-es256 message key)
    (begin
      (import es256)
      (sign message key)))

  (define (sign-hs256 message key)
    (begin
      (import hs256)
      (sign message key)))

  (define (sign-rs256 message key)
    (begin
      (import rs256)
      (sign message key)))

  (define (verify-es256 message key signature)
    (begin
      (import es256)
      (verify message key signature)))

  (define (verify-hs256 message key signature)
    (begin
      (import hs256)
      (verify message key signature)))

  (define (verify-rs256 message key signature)
    (begin
      (import rs256)
      (verify message key signature))))
