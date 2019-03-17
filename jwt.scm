(include "algorithms")
(include "claims")
(include "urlsafe-base64")

(module jwt (jwt-encode jwt-decode)
  (import algorithms chicken.base chicken.string claims medea scheme srfi-1
          urlsafe-base64 utf8
          (only srfi-13 string-join)
          (only srfi-133 vector-append))

  (define (algorithm-error algorithm)
    (error "Algorithm not supported" algorithm))

  (define (sign message key algorithm)
    (case algorithm
      ((none) "")
      ((ES256) (sign-es256 message key))
      ((HS256) (sign-hs256 message key))
      ((RS256) (sign-rs256 message key))
      (else (algorithm-error algorithm))))

  (define (verify signing-input key signature algorithm)
    (case algorithm
      ((none) #f)
      ((ES256) (verify-es256 signing-input key signature))
      ((HS256) (verify-hs256 signing-input key signature))
      ((RS256) (verify-rs256 signing-input key signature))
      (else (algorithm-error algorithm))))

  (define (make-header algorithm headers)
    (let ((base-header `((typ . "JWT") (alg . ,algorithm))))
      (if headers (vector-append base-header headers) base-header)))

  (define (jwt-encode payload key #!optional (algorithm "HS256") headers)
    (let* ((encoded-header (urlsafe-base64-encode (json->string (make-header algorithm headers))))
           (encoded-payload (urlsafe-base64-encode (json->string payload)))
           (signing-input (string-join `(,encoded-header ,encoded-payload) "."))
           (encoded-signature (urlsafe-base64-encode (sign signing-input key (string->symbol algorithm)))))
      (string-join `(,encoded-header ,encoded-payload ,encoded-signature) ".")))

  (define (jwt-decode jwt key #!optional
                      (algorithm "HS256")
                      (verify-signature-p #t)
                      claims-spec)
    (let*-values (((encoded-header encoded-payload encoded-signature)
                   (apply values (string-split jwt "." #t)))
                  ((signing-input) (string-join `(,encoded-header ,encoded-payload) "."))
                  ((decoded-header) (read-json (urlsafe-base64-decode encoded-header)))
                  ((decoded-signature) (urlsafe-base64-decode encoded-signature)))
      (begin
        (if verify-signature-p
            (let ((header-algorithm (cdr (assoc 'alg decoded-header))))
              (begin
                (unless (equal? algorithm header-algorithm)
                  (error "Unexpected algorithm" header-algorithm))
                (unless (verify signing-input key decoded-signature (string->symbol algorithm))
                  (error "Invalid signature" decoded-signature)))))
        (let ((claims (read-json (urlsafe-base64-decode encoded-payload))))
          (begin
            (and claims-spec (validate-claims claims claims-spec))
            claims))))))
