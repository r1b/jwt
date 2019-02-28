; * https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
; * How to distinguish symmetric / asymmetric signatures?
;   * Load raw key instead of PEM
;   * Verify via constant time equals instead of calling DigestVerify*
(define-interface signature-interface (load-key message-digest verify-signature))

(functor (signature-functor (algorithm (interface: signature-interface)) (sign verify))
  (import algorithm scheme)
  (define (sign message key) 42)
  (define (verify message key signature) 42))

(define (load-pem key) 42)
(define (load-raw key) 42)
(define (verify-asymmetric) 42)
(define (verify-symmetric) 42)

(module ecdsa (interface: signature-interface)
  (define (load-key key) (load-pem key))
  (define message-digest "sha256")
  (define (verify-signature message key signature)
    (verify-asymmetric message key signature)))

(module hmac-sha-256 (interface: signature-interface)
  (define (load-key key) (load-raw key))
  (define message-digest "sha256")
  (define (verify-signature message key signature)
    (verify-symmetric message key signature)))

(module rsa (interface: signature-interface)
  (define (load-key key) (load-pem key))
  (define message-digest "sha256")
  (define (verify-signature message key signature)
    (verify-asymmetric message key signature)))

(module es256 = (signature-functor ecdsa))
(module hs256 = (signature-functor hmac-sha-256))
(module rs256 = (signature-functor rsa))
