; FIXME: Probably need to flesh out the interface for loading keys if we want
; to support verifying that users are providing the correct type of keys a la
; pyjwt.

; I'm also starting to think that the HMAC stuff should be pulled out entirely
; into its own functor...HMACs are not really "digital signatures" - OpenSSL
; just happens to conflate them with the EVP_DigestSign* family. When I look
; at sources for e.g python cryptopgrahy, node crypto nobody does this but I
; imagine that's bc these implementations are much older.

; See discussion https://stackoverflow.com/questions/12545811/using-hmac-vs-evp-functions-in-openssl
(define-interface signature-interface (get-message-digest load-key make-verify))
