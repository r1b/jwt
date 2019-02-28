(import
  (chicken blob)
  (chicken foreign)
  (chicken io)
  scheme)

#>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
<#

(define (foreign-error)
  (error ((foreign-lambda c-string "ERR_error_string" unsigned-long c-string)
          ((foreign-lambda unsigned-long "ERR_get_error")) #f)))

(define (rsa-sign message key)
  (let* ((bio (or ((foreign-lambda c-pointer "BIO_new_mem_buf" scheme-pointer int)
                   key (blob-size key))
                  (foreign-error)))
         (pkey (or ((foreign-lambda c-pointer "PEM_read_bio_PrivateKey" c-pointer c-pointer c-pointer c-pointer)
                    bio #f #f #f)
                   (foreign-error)))
         (ctx ((foreign-lambda c-pointer "EVP_MD_CTX_create")))
         (type ((foreign-lambda c-pointer "EVP_sha256")))
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
      ((foreign-lambda void "BIO_free" c-pointer) bio)
      (blob->string signature))))

(define (rsa-verify message key signature) 42)

; Fingers cross'd
(display (rsa-sign
           (string->blob (read-string #f (open-input-file "test.message")))
           (string->blob (read-string #f (open-input-file "test.pem")))))
