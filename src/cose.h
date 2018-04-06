#ifndef RS_HTTP_COSE_H
#define RS_HTTP_COSE_H

#include "types.h"

typedef struct cose_sign1 {
    bytes payload;
    bytes external_aad;
    bytes protected_header;
    bytes unprotected_header;
} cose_sign1;

typedef struct cose_encrypt0 {
    bytes plaintext;
    bytes external_aad;
} cose_encrypt0;

void cose_encode_signed(cose_sign1* sign1,
                        uint8_t* out,
                        size_t out_size,
                        size_t* out_len);

void cose_sign1_structure(const char* context,
                          bytes* body_protected,
                          bytes* external_aad,
                          bytes* payload,
                          uint8_t* out,
                          size_t out_size,
                          size_t* out_len);

void cose_encode_encrypted(cose_encrypt0 *enc0, uint8_t *key, uint8_t *iv, 
                           uint8_t *out, size_t out_size, size_t *out_len);
void cose_enc0_structure(bytes* body_protected, bytes* external_aad,
                         uint8_t* out, size_t out_size, size_t* out_len);

void cose_kdf_context(const char* algorithm_id, int key_length, bytes other, uint8_t* out, size_t out_size, size_t *out_len);
void derive_key(bytes input_key, bytes info, uint8_t* out, size_t out_size);

void cose_decrypt_enc0(bytes* enc0, uint8_t *key, uint8_t *iv, bytes* external_aad,
                       uint8_t* out, size_t out_size, size_t *out_len);
int cose_verify_sign1(bytes* sign1, uint8_t *pub_key, bytes* external_aad);


#endif //RS_HTTP_COSE_H
