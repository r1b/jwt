(include "algorithms")
(include "urlsafe-base64")

(module jwt (jwt-encode jwt-decode)
  (import chicken.base chicken.string medea scheme srfi-1 urlsafe-base64 utf8
          (only srfi-13 string-join)
          (only srfi-133 vector-append))

  (define (sign message key algorithm)
    (cond
      ((equal? algorithm "none") "")
      ((equal? algorithm "ES256")
       (begin
         (import es256)
         (sign message key)))
      ((equal? algorithm "HS256")
       (begin
         (import hs256)
         (sign message key)))
      ((equal? algorithm "RS256")
       (begin
         (import rs256)
         (sign message key)))
      (else (error "Algorithm not supported" algorithm))))

  (define (verify signing-input key signature algorithm)
    (cond
      ((equal? algorithm "none") #f)
      ((equal? algorithm "ES256")
       (begin
         (import es256)
         (verify signing-input key signature)))
      ((equal? algorithm "HS256")
       (begin
         (import hs256)
         (verify signing-input key signature)))
      ((equal? algorithm "RS256")
       (begin
         (import rs256)
         (verify signing-input key signature)))
      (else (error "Algorithm not supported" algorithm))))

  (define (make-header algorithm headers)
    (let ((base-header `((typ . "JWT") (alg . ,algorithm))))
      (if headers (vector-append base-header headers) base-header)))

  (define (jwt-encode payload key #!optional (algorithm "HS256") headers)
    (let* ((encoded-header (urlsafe-base64-encode (json->string (make-header algorithm headers))))
           (encoded-payload (urlsafe-base64-encode (json->string payload)))
           (signing-input (string-join `(,encoded-header ,encoded-payload) "."))
           (encoded-signature (urlsafe-base64-encode (sign signing-input key algorithm))))
      (string-join `(,encoded-header ,encoded-payload ,encoded-signature) ".")))

  (define (jwt-decode jwt key algorithm #!optional (verify-signature-p #t))
    (let*-values (((encoded-header encoded-payload encoded-signature)
                   (apply values (string-split jwt ".")))
                  ((signing-input) (string-join `(,encoded-header ,encoded-payload) "."))
                  ((decoded-header) (read-json (urlsafe-base64-decode encoded-header)))
                  ((decoded-signature) (urlsafe-base64-decode encoded-signature)))
      (begin
        (if verify-signature-p
            (let ((header-algorithm (cdr (assoc 'alg decoded-header))))
              (begin
                (unless (equal? algorithm header-algorithm)
                  (error "Unexpected algorithm" header-algorithm))
                (unless (verify signing-input key decoded-signature algorithm)
                  (error "Invalid signature" decoded-signature)))))
        (read-json (urlsafe-base64-decode encoded-payload))))))
