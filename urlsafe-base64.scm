(module urlsafe-base64 (urlsafe-base64-encode urlsafe-base64-decode)
  (import base64 (only chicken.string string-translate) scheme)

  ; string -> string
  (define (urlsafe-base64-encode s #!optional (altchars '(#\- #\_)))
    (string-translate (base64-encode s) '(#\+ #\/) altchars))

  ; string -> string
  (define (urlsafe-base64-decode s #!optional (altchars '(#\- #\_)))
    (base64-decode (string-translate s altchars '(#\+ #\/)))))
