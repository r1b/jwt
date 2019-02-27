(import (chicken blob) (chicken file posix) (chicken foreign) scheme)

#>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
<#

; dear gentle reader, this is not a real key that I use :)
(define test-key "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA6Q0G/xAU5ZfPGLNsJ1MQVPJrt6n92nOSs6UHTpFwxzJpM3Bb
lAqo7OoLtGfJ35DSAFDhb9Ku8Y4DssVjVx9pZPGJwd3HupAIjpN05+GHf2x3vi++
fKD7szbRDjvWBXTmQ3oWuFDewyD3Vxf4yad4951NdxNwmweK69Z2zCpvQpH0ZvX0
RG58uEV4Ow4uTsEtSzPKntXbQEFjarz272DLm67kLSDpMlUmZennHUYsLriq9AC3
3Famqm2c9rlT14H7MC6Py4ZiPZEKhpqLHwpylxAFfmOw00qaAwDlYrVbJUOFsI1L
mHEStOJUhE/JJZ7Ypf/K0Hc6RT0/8eHW9V2ZPQIDAQABAoIBAQC8CtbqV3+FAckI
lT1fPZaf9DsWJwO9kCN+8FnE+3WURQi9iJtcCH3lK7PmDRjGW4QW3SwJnmWqYnx5
cuuFEMNpv7r3wou17SH6aOCbeU5rconr23pH9V0ibcihQ4adQIXLTGeosRgNOjxY
+e60R31DzpkCy5zAeoWNZa7Vbif3/WJkVZ89skV+9UkYdZiPrPDOnXMlpGJaalsp
9sm6/Thwii/FihI5mmoNwkAdlVadAwX5B7Oni1aPMyZXNJNcSqbBsLd09ke8vlWY
/OZ3Vq/vvXKgIMEDv72UrknY3i48BjVTY9jiePj2dcDddI0H1S0JskTOkye0LuHk
5UDrE/wBAoGBAPxnNKLgF9oamsZ2TX6EgCxvwmc8QfZdMDslK1B0h6mHQt4AgJDp
JFe9sJAVzH9/LiOgEcRggTJpp6cHp8zSyq1h4apdI89Io+Qw5is7Dm7PErcSHQIg
EcFuIHBZHa74/AhrkV9k68OX/5mV9F2AKdhUTDq45E6gBbVi4bYiB3YtAoGBAOxf
OPlOQWVq9PAiLID6yy/RiWRMsq8PKCKsgG/JH/2vZ0wysqo4Fq+iWuPFm/fi7UYM
rtTkLNYcAtDvoqIf6d6X425ZoxzlQBiqqhNDgSFqqi6ZawE/ulmbF+ytEXrv/r/W
VD5GzIPxNJF5rbU/0ij9getVgIhO5Xu+6aMb5ClRAoGBANJ2YE6b22ezHXH1PYMM
izACdLDObxY1+DypLqfksyZqMhiZhJrQvMwo0OwkMSPy8Y8lLwt3iON3dCNz37iL
4BKY9qmvBmgWYwqot5Q+pzdAlZNvmB6ojQWkhYoI1RaMaOPAhjRsG6c5vBjeEChS
8RGAoRuqBj2Fc50e+aR8VYp1AoGASWG+lFdhIhU0eaCCZIB3uB67IrJU/tgbw7f+
H7Y3AlEEJrnOkd3b3SbwRKpCo5CFzSt+04ULDmWf0jGzMdXqizpoVwfpBb1+Sqoh
Jt3cJv2wW8sxVy/rsInfwZBxTtNXKUNm3/am44dspIU8Enr/yc36GY9v2eF0iRhZ
/FNaYCECgYAeUV17ohFW586f8Y3d9fgkaUYL0WZ+5Nj0tqqPLkzHklQfzXZESPHg
6F+5WjPSqd2qa+opQAXBB34vZ3K9bRYX9rZxXR5a+wsP/Tq5MQo2Qw6pkAXrZWhe
bzRSAkVIWUQcQ+c3nIl9fNFU/kRONjz9xuLSESobAOD41bCq6rFlvA==
-----END RSA PRIVATE KEY-----")

(define (foreign-error)
  (begin
    ((foreign-lambda* void ((scheme-object port))
       "ERR_print_errors_fp(C_port_file(port));")
     (current-error-port))
    (error "libcrypto: whoops")))

(define (rsa-sign message key)
  (let* ((bio (or ((foreign-lambda* c-pointer ((scheme-pointer buf) (int len))
                     "C_return(BIO_new_mem_buf(buf, len));")
                   key (blob-size key))
                  (foreign-error)))
         (rsa (or ((foreign-lambda* c-pointer ((c-pointer bio))
                     "C_return(PEM_read_bio_RSAPrivateKey(bio,NULL,NULL,NULL));")
                   bio)
                  (foreign-error)))
         (signature-length ((foreign-lambda* int ((c-pointer rsa)) "C_return(RSA_size(rsa));")
                            rsa))
         (signature (make-blob signature-length)))
    (begin
      ((foreign-lambda* int
         ((blob m) (int m_len) (scheme-pointer sigret) (unsigned-int siglen) (c-pointer rsa))
         "C_return(RSA_sign(NID_sha256, m, m_len, sigret, &siglen, rsa));")
       message (blob-size message) signature signature-length rsa)
      ((foreign-lambda void "RSA_free" c-pointer) rsa)
      ((foreign-lambda void "BIO_free" c-pointer) bio)
      (blob->string signature))))

(define (rsa-verify message key signature) 42)

; Fingers cross'd
(display (rsa-sign (string->blob "god is love") (string->blob test-key)))
