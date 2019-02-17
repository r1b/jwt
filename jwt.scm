(include "constant-time-equal.scm")
(include "urlsafe-base64.scm")

(module jwt (jwt-encode jwt-decode)
  (import chicken.base chicken.string constant-time-equal hmac medea scheme sha2 urlsafe-base64
          (only srfi-13 string-join)
          (only srfi-133 vector-append))

  (define (sign message key algorithm)
    (case algorithm
      (("none") "")
      (("HS256") ((hmac key (sha256-primitive)) message))
      (else (error "Algorithm not supported" algorithm))))

  (define (verify signing-input key signature algorithm)
    (case algorithm
      (("none") #f)
      (("HS256") (constant-time-equal? ((hmac key (sha256-primitive)) signing-input) signature))
      (else (error "Algorithm not supported" algorithm))))

  (define (make-header algorithm headers)
    (let ((base-header `(("typ" . "JWT") ("alg" . ,algorithm))))
      (if headers (vector-append base-header headers) base-header)))

  (define (jwt-encode payload key #!optional (algorithm "HS256") headers)
    (let* ((encoded-header (urlsafe-base64-encode (write-json (make-header algorithm headers))))
           (encoded-payload (urlsafe-base64-encode (write-json payload)))
           (signing-input (string-join '(encoded-header encoded-payload) "."))
           (encoded-signature (urlsafe-base64-encode (sign signing-input key algorithm))))
      (string-join '(encoded-header encoded-payload encoded-signature) ".")))

  (define (jwt-decode jwt key algorithm #!optional (verify-signature #t))
    (let*-values (((encoded-header encoded-payload encoded-signature)
                   (apply values (string-split jwt ".")))
                  (signing-input (string-join '(encoded-header encoded-payload) "."))
                  (decoded-header (read-json (urlsafe-base64-decode encoded-header)))
                  (decoded-signature (read-json (urlsafe-base64-decode encoded-signature))))
      (begin
        (if verify-signature
            (let ((header-algorithm (assoc "alg" decoded-header)))
              (begin
                (unless (equal? algorithm header-algorithm)
                  (error "Unexpected algorithm" header-algorithm))
                (unless (verify signing-input key decoded-signature algorithm)
                  (error "Invalid signature" decoded-signature)))))
        (read-json (urlsafe-base64-decode encoded-payload))))))
