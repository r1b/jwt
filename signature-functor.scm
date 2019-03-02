(include "signature-interface")

(functor (signature-functor (ALG signature-interface)) (sign verify)
  (import ALG (chicken base) (chicken blob) (chicken foreign) scheme signature)

  (define (sign message key)
    ((make-sign get-message-digest load-key) message key))

  (define (verify message key signature)
    ((make-verify get-message-digest load-key verify-signature) message key)))
