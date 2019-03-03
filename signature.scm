#>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
<#

; Fingers cross'd
; (display (rsa-sign
;           (string->blob (read-string #f (open-input-file "test.message")))
;           (string->blob (read-string #f (open-input-file "test.pem")))))

(module signature
  (get-message-digest-by-name
   load-pem-private-key
   load-raw-private-key
   make-sign
   make-verify
   verify-asymmetric
   verify-symmetric)

  (import
    (chicken base)
    (chicken blob)
    (chicken foreign)
    (chicken io)
    scheme)

  (define (foreign-error)
    (error ((foreign-lambda c-string "ERR_error_string" unsigned-long c-string)
            ((foreign-lambda unsigned-long "ERR_get_error")) #f)))

  ; string -> EVP_MD *
  (define (get-message-digest-by-name name)
    (or ((foreign-lambda c-pointer "EVP_get_digestbyname" c-string) name)
        (foreign-error)))

  ; blob -> c-pointer
  (define (make-bio key)
    (or ((foreign-lambda c-pointer "BIO_new_mem_buf" scheme-pointer int)
         key (blob-size key))
        (foreign-error)))

  ; blob -> EVP_PKEY *
  (define (load-pem-private-key key)
    (let ((bio (make-bio key)))
      (begin
        (or ((foreign-lambda c-pointer "PEM_read_bio_PrivateKey" c-pointer c-pointer c-pointer c-pointer)
             bio #f #f #f)
            (foreign-error))
        ((foreign-lambda void "BIO_free" c-pointer) bio))))

  ; blob -> EVP_PKEY *
  ; FIXME: Use EVP_PKEY_new_raw_private_key
  (define (load-raw-private-key key #!optional (type (foreign-value "EVP_PKEY_HMAC" int)))
    (or ((foreign-lambda c-pointer "EVP_PKEY_new_mac_key" int c-pointer blob size_t)
         type #f key (blob-size key))
        (foreign-error)))

  (define (make-sign get-message-digest load-key)
    (lambda (message key)
      (let* ((pkey (load-key key))
             (ctx ((foreign-lambda c-pointer "EVP_MD_CTX_create")))
             (type (get-message-digest))
             (signature-length ((foreign-lambda int "EVP_PKEY_size" c-pointer)
                                pkey))
             (signature (make-blob signature-length)))
        (begin
          ((foreign-lambda void "EVP_MD_CTX_init" c-pointer) ctx)
          ((foreign-lambda int "EVP_DigestSignInit"
                           c-pointer c-pointer c-pointer c-pointer c-pointer)
           ctx #f type #f pkey)
          ((foreign-lambda int "EVP_DigestSignUpdate"
                           c-pointer scheme-pointer unsigned-int)
           ctx message (blob-size message))
          ((foreign-lambda* int ((c-pointer ctx) (blob sig) (size_t siglen))
             "C_return(EVP_DigestSignFinal(ctx, sig, &siglen));")
           ctx signature signature-length)
          ((foreign-lambda void "EVP_MD_CTX_destroy" c-pointer) ctx)
          ((foreign-lambda void "EVP_PKEY_free" c-pointer) pkey)
          (blob->string signature)))))

  (define (verify-asymmetric message key signature) 42)
  (define (verify-symmetric message key signature) 42)

  (define (make-verify message key signature) 42))
