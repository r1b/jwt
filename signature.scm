#>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
<#

(include "constant-time-equal")

(module signature
  (get-message-digest-by-name
    load-private-key
    load-public-key
    load-secret-key
    make-sign
    make-asymmetric-verify
    make-symmetric-verify)

  (import
    (chicken base)
    (chicken blob)
    (chicken foreign)
    (chicken io)
    constant-time-equal
    scheme
    string-hexadecimal)

  ; TODO set OPENSSL_API_COMPAT (?)
  ; We are already using some 1.1.0 specific features
  (foreign-code "OpenSSL_add_all_digests();")

  (define (foreign-error)
    (error ((foreign-lambda c-string "ERR_error_string" unsigned-long c-string)
            ((foreign-lambda unsigned-long "ERR_get_error")) #f)))

  ; string -> EVP_MD *
  (define (get-message-digest-by-name name)
    (or ((foreign-lambda c-pointer "EVP_get_digestbyname" c-string) name)
        (foreign-error)))

  ; string -> c-pointer
  (define (make-bio key)
    (or ((foreign-lambda c-pointer "BIO_new_mem_buf" blob int)
         (string->blob key) (string-length key))
        (foreign-error)))

  ; string -> EVP_PKEY *
  (define (load-private-key key)
    (let* ((bio (make-bio key))
          (pkey (or ((foreign-lambda c-pointer "PEM_read_bio_PrivateKey"
                                     c-pointer c-pointer c-pointer c-pointer)
                     bio #f #f #f)
                    (foreign-error))))
      (begin
        ((foreign-lambda void "BIO_free" c-pointer) bio)
        pkey)))

  ; string -> EVP_PKEY *
  (define (load-public-key key)
    (let* ((bio (make-bio key))
          (pkey (or ((foreign-lambda c-pointer "PEM_read_bio_PUBKEY"
                                     c-pointer c-pointer c-pointer c-pointer)
                     bio #f #f #f)
                    (foreign-error))))
      (begin
        ((foreign-lambda void "BIO_free" c-pointer) bio)
        pkey)))

  ; string -> EVP_PKEY *
  (define (load-secret-key key #!optional (type (foreign-value "EVP_PKEY_HMAC" int)))
    (or ((foreign-lambda c-pointer "EVP_PKEY_new_raw_private_key" int c-pointer blob size_t)
         type #f (string->blob key) (string-length key))
        (foreign-error)))

  ; string -> EVP_MD * -> string string -> string
  (define ((make-sign get-message-digest load-key) message key)
    (let* ((pkey (load-key key))
           (ctx ((foreign-lambda c-pointer "EVP_MD_CTX_create"))))
      (let-location ((signature-length size_t))
        (begin
          ((foreign-lambda void "EVP_MD_CTX_init" c-pointer) ctx)
          (or (positive? ((foreign-lambda int "EVP_DigestSignInit"
                                          c-pointer c-pointer c-pointer c-pointer c-pointer)
                          ctx #f (get-message-digest) #f pkey))
              (foreign-error))
          (or (positive? ((foreign-lambda int "EVP_DigestSignUpdate"
                                          c-pointer blob unsigned-int)
                          ctx (string->blob message) (string-length message)))
              (foreign-error))
          ; signature is NULL to get length in signature-length
          (or (positive? ((foreign-lambda int "EVP_DigestSignFinal"
                                          c-pointer blob (c-pointer size_t))
                          ctx #f (location signature-length)))
              (foreign-error))
          (let ((signature (make-blob signature-length)))
            (begin
              ; now we actually sign it
              (or (positive? ((foreign-lambda int "EVP_DigestSignFinal"
                                              c-pointer blob (c-pointer size_t))
                              ctx signature (location signature-length)))
                  (foreign-error))
              ((foreign-lambda void "EVP_MD_CTX_destroy" c-pointer) ctx)
              ((foreign-lambda void "EVP_PKEY_free" c-pointer) pkey)
              (blob->string signature)))))))

  (define ((make-asymmetric-verify get-message-digest) message key signature)
    (let* ((pkey (load-public-key key))
           (ctx ((foreign-lambda c-pointer "EVP_MD_CTX_create")))
           (type (get-message-digest))
           (signature-length (string-length signature)))
      (begin
        ((foreign-lambda void "EVP_MD_CTX_init" c-pointer) ctx)
        ((foreign-lambda int "EVP_DigestVerifyInit"
                         c-pointer c-pointer c-pointer c-pointer c-pointer)
         ctx #f type #f pkey)
        ((foreign-lambda int "EVP_DigestVerifyUpdate"
                         c-pointer blob unsigned-int)
         ctx (string->blob message) (string-length message))

        (let ((verified (= ((foreign-lambda int "EVP_DigestVerifyFinal"
                                            c-pointer blob size_t)
                            ctx (string->blob signature) signature-length) 1)))
          (begin
            ((foreign-lambda void "EVP_MD_CTX_destroy" c-pointer) ctx)
            ((foreign-lambda void "EVP_PKEY_free" c-pointer) pkey)
            verified)))))

  (define ((make-symmetric-verify get-message-digest) message key signature)
    (constant-time-equal? signature
                          ((make-sign get-message-digest load-secret-key) message key))))
