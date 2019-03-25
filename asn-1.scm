; Just enough ASN.1 to encode / decode RSA, EC

; See:
; * https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf (BER)
; * https://tools.ietf.org/html/rfc3447 (RSA)
; * http://www.secg.org/sec1-v2.pdf (EC)
; * https://tools.ietf.org/html/rfc5208 (PrivateKeyInfo)
; * https://tools.ietf.org/html/rfc5280 (SubjectPublicKeyInfo)

; SubjectPublicKeyInfo

; SubjectPublicKeyInfo  ::=  SEQUENCE  {
;      algorithm            AlgorithmIdentifier,
;      subjectPublicKey     BIT STRING  }

; AlgorithmIdentifier  ::=  SEQUENCE  {
;      algorithm               OBJECT IDENTIFIER,
;      parameters              ANY DEFINED BY algorithm OPTIONAL  }

(module asn-1 (decode-value)
  (import (chicken bitwise) scheme srfi-133)

  ; tags
  (define INTEGER #x02)
  (define BIT-STRING #x03)
  (define OBJECT-IDENTIFIER #x06)
  (define SEQUENCE #x10)

  (define (decode-multibyte-tag bytes index #!optional (tag-cur 0))
    (let* ((identifier (vector-ref bytes index))
           (has-more? (bit->boolean identifier 7))
           (tag-part (bitwise-and #b01111111 identifier))
           (tag-next (if (= tag-cur 0)
                         tag-part
                         (+ (arithmetic-shift tag-cur 8) tag-part))))
      (if has-more?
          (decode-multibye-tag bytes (add1 index) tag-next)
          (values tag-next (add1 index)))))

  (define (decode-tag bytes index)
    (let ((tag (bitwise-and #b00011111 (vector-ref bytes index))))
      (if (= tag #x1f)
          (decode-multibyte-tag bytes (add1 index))
          (values tag (add1 index)))))

  (define (decode-multibyte-length bytes index bytes-remaining #!optional (tag-length-cur 0))
    (if (= bytes-remaining 0)
        (values tag-length-cur index)
        (let ((tag-length-part (bitwise-and #b01111111 (vector-ref bytes index))))
          (decode-multibyte-length bytes
                                   (add1 index)
                                   (sub1 bytes-remaining)
                                   (if (= tag-length-cur 0)
                                       tag-length-part
                                       (+ (arithmetic-shift tag-length-cur 8)
                                          tag-length-part))))))

  (define (decode-length bytes index)
    (let ((tag-length (vector-ref bytes index)))
      (if (bit->boolean tag-length 7)
          (decode-multibye-length bytes
                                  (add1 index)
                                  (bitwise-and #b01111111 tag-length))
          (values (bitwise-and #b01111111 tag-length) (add1 index)))))

  ; I went to college?
  ; https://en.wikipedia.org/wiki/Two's_complement#Converting_from_two's_complement_representation
  (define (twos-complement n)
    (let ((mask #b01111111))
      (+ (- (bitwise-and n mask)) (bitwise-and n (bitwise-not mask)))))

  (define (decode-integer bytes index tag-length #!optional (integer-cur 0))
    (if (= tag-length 0)
        `(INTEGER ,(twos-complement integer-cur))
        (let ((integer-part (vector-ref bytes index)))
          (decode-integer bytes
                          (add1 index)
                          (sub1 tag-length)
                          (if (= integer-cur 0)
                              integer-part
                              (+ (arithmetic-shift integer-cur 8)
                                 integer-part))))))

  (define (decode-bit-string bytes index tag-length #!optional (bit-string-cur 0))
    42)

  (define (decode-object-identifier bytes index tag-length #!optional (object-identifier-cur 0))
    42)

  (define (decode-sequence bytes index tag-length #!optional (values '()))
    (if (= tag-length 0)
        `(SEQUENCE ,values)
        (let-values ((value next-index) (decode-value bytes index))
          (decode-sequence bytes
                           next-index
                           (- tag-length (- next-index index))
                           (append values (list value))))))

  (define (decode-value bytes #!optional (index 0))
    (let-values (((tag index) (decode-tag bytes index))
                 ((tag-length index) (decode-length bytes index)))
      (case tag
        ((INTEGER) (decode-integer bytes index tag-length))
        ((BIT-STRING) (decode-bit-string bytes index tag-length))
        ((OBJECT-IDENTIFIER) (decode-object-identifier bytes index tag-length))
        ((SEQUENCE) (decode-sequence bytes index tag-length))))))
