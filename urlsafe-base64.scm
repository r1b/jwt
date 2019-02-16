; Base64url encoding as described in RFC7515
(module urlsafe-base64 (urlsafe-base64-encode urlsafe-base64-decode)

  (import base64 scheme (only chicken.string string-split string-translate))

  ; string -> string
  (define (urlsafe-base64-encode s #!optional (altchars '(#\- #\_)))
    (let ((encoded-with-padding (string-translate (base64-encode s) '(#\+ #\/) altchars)))
      (car (string-split encoded-with-padding "=" #t))))

  ; string -> string
  (define (urlsafe-base64-decode s #!optional (altchars '(#\- #\_)))
    (let* ((padding (make-string (- 4 (modulo (string-length s) 4)) #\=))
           (encoded-with-padding (string-append s padding)))
      (base64-decode (string-translate encoded-with-padding altchars '(#\+ #\/))))))
