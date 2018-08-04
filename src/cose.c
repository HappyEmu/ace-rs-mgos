#include "cose.h"
#include "utils.h"
#include "cbor.h"
#include "cryptoauthlib.h"
#include "mbedtls/ccm.h"
#include "hkdf.h"

#define DIGEST_SIZE 32
#define TAG_SIZE 8

void cose_encode_signed(cose_sign1* sign1,
                        uint8_t* out, size_t out_size, size_t* out_len) {
    uint8_t sign_structure[256];
    size_t sign_struct_len = sizeof(sign_structure);

    cose_sign1_structure("Signature1", &sign1->protected_header, &sign1->external_aad, &sign1->payload,
                         sign_structure, sizeof(sign_structure), &sign_struct_len);

    //printf("to_verify: ");
    //phex(sign_structure, sign_struct_len);

    // Hash sign structure
    uint8_t digest[DIGEST_SIZE];
    atcab_sha((uint16_t) sign_struct_len, (const uint8_t*) sign_structure, digest);

    // Compute signature
    uint8_t signature[64];
    atcab_sign(0, digest, signature);

    // Encode sign1 structure
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cbor_encode_tag(&enc, 18);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_byte_string(&ary, sign1->protected_header.buf, sign1->protected_header.len);
    cbor_encode_byte_string(&ary, sign1->unprotected_header.buf, sign1->unprotected_header.len);
    cbor_encode_byte_string(&ary, sign1->payload.buf, sign1->payload.len);
    cbor_encode_byte_string(&ary, signature, sizeof(signature));

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_sign1_structure(const char* context,
                          bytes* body_protected,
                          bytes* external_aad,
                          bytes* payload,
                          uint8_t* out,
                          size_t out_size,
                          size_t* out_len) {

    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_text_stringz(&ary, context);
    cbor_encode_byte_string(&ary, body_protected->buf, body_protected->len);
    cbor_encode_byte_string(&ary, external_aad->buf, external_aad->len);
    cbor_encode_byte_string(&ary, payload->buf, payload->len);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_encode_encrypted(cose_encrypt0 *enc0, 
                           uint8_t *key,
                           uint8_t *iv, size_t iv_len, 
                           uint8_t *out, size_t out_size, size_t *out_len) {
    // Compute aad
    uint8_t aad[128];
    size_t aad_len;
    cose_enc0_structure(&enc0->protected_header, &enc0->external_aad, aad, sizeof(aad), &aad_len);

    // Encrypt
    uint8_t ciphertext[enc0->plaintext.len + TAG_SIZE];

    mbedtls_ccm_context ccm;
    mbedtls_ccm_init(&ccm);
    mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, 128);

    mbedtls_ccm_encrypt_and_tag(&ccm, 
                                enc0->plaintext.len, 
                                iv, iv_len, 
                                aad, aad_len, 
                                enc0->plaintext.buf, 
                                ciphertext, ciphertext+enc0->plaintext.len, TAG_SIZE);
    
    mbedtls_ccm_free(&ccm);

    // Encode
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cbor_encode_tag(&enc, 16);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 3);

    cbor_encode_byte_string(&ary, enc0->protected_header.buf, enc0->protected_header.len);
    cbor_encode_byte_string(&ary, NULL, 0);
    cbor_encode_byte_string(&ary, ciphertext, sizeof(ciphertext));

    cbor_encoder_close_container(&enc, &ary);

    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_enc0_structure(bytes* body_protected, bytes* external_aad,
                         uint8_t* out, size_t out_size, size_t* out_len) {

    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 3);

    cbor_encode_text_stringz(&ary, "Encrypt0");
    cbor_encode_byte_string(&ary, body_protected->buf, body_protected->len);
    cbor_encode_byte_string(&ary, external_aad->buf, external_aad->len);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_kdf_context(const char* algorithm_id, int key_length, bytes *other, uint8_t* out, size_t out_size, size_t *out_len) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);
    cbor_encode_text_stringz(&ary, algorithm_id);

    CborEncoder partyUInfo;
    cbor_encoder_create_array(&ary, &partyUInfo, 3);
    cbor_encode_null(&partyUInfo);
    cbor_encode_null(&partyUInfo);
    cbor_encode_null(&partyUInfo);
    cbor_encoder_close_container(&ary, &partyUInfo);

    CborEncoder partyVInfo;
    cbor_encoder_create_array(&ary, &partyVInfo, 3);
    cbor_encode_null(&partyVInfo);
    cbor_encode_null(&partyVInfo);
    cbor_encode_null(&partyVInfo);
    cbor_encoder_close_container(&ary, &partyVInfo);

    CborEncoder suppPubInfo;
    cbor_encoder_create_array(&ary, &suppPubInfo, 3);
    cbor_encode_int(&suppPubInfo, key_length);
    cbor_encode_byte_string(&suppPubInfo, NULL, 0);
    cbor_encode_byte_string(&suppPubInfo, other->buf, other->len);
    cbor_encoder_close_container(&ary, &suppPubInfo);

    cbor_encoder_close_container(&enc, &ary);

    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void derive_key(bytes *input_key, bytes *info, uint8_t* out, size_t out_size) {
    // TODO
    const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_hkdf(sha256, NULL, 0, input_key->buf, input_key->len, info->buf, info->len, out, out_size);
    /*int mbedtls_hkdf( const mbedtls_md_info_t *md, const unsigned char *salt,
                  size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                  const unsigned char *info, size_t info_len,
                  unsigned char *okm, size_t okm_len )*/
    // wc_HKDF(SHA256, input_key.buf, (word32) input_key.len, NULL, 0, info.buf, (word32) info.len, out, (word32) out_size);
}

void cose_decrypt_enc0(bytes* enc0, uint8_t *key, uint8_t *iv, size_t iv_len, bytes* external_aad,
                       uint8_t* out, size_t out_size, size_t *out_len) {
    // Parse encoded enc0
    CborParser parser;
    CborValue val;
    cbor_parser_init(enc0->buf, enc0->len, 0, &parser, &val);

    CborTag tag;
    cbor_value_get_tag(&val, &tag);
    cbor_value_advance(&val);

    CborValue e;
    cbor_value_enter_container(&val, &e);

    bytes protected;
    cbor_value_dup_byte_string(&e, &protected.buf, &protected.len, &e);

    // Skip unprotected header
    cbor_value_advance(&e);

    bytes ciphertext;
    cbor_value_dup_byte_string(&e, &ciphertext.buf, &ciphertext.len, &e);
    cbor_value_leave_container(&val, &e);

    // Compute AAD
    uint8_t aad[64];
    size_t aad_len;
    cose_enc0_structure(&protected, external_aad, aad, sizeof(aad), &aad_len);

    // Allocate Resources
    uint8_t plaintext[ciphertext.len - TAG_SIZE];
    uint8_t auth_tag[TAG_SIZE];
    memcpy(auth_tag, ciphertext.buf + ciphertext.len - TAG_SIZE, TAG_SIZE);

    // Decrypt
    mbedtls_ccm_context ccm;
    mbedtls_ccm_init(&ccm);
    mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, 128);

    mbedtls_ccm_auth_decrypt(&ccm, sizeof(plaintext), iv, 13, aad, aad_len, ciphertext.buf, plaintext, auth_tag, TAG_SIZE);

    mbedtls_ccm_free(&ccm);
    phex(plaintext, sizeof(plaintext));

    // Return plaintext to caller
    memcpy(out, plaintext, sizeof(plaintext));
    *out_len = sizeof(plaintext);

    // Clean up
    free(protected.buf);
    free(ciphertext.buf);
}

int cose_verify_sign1(bytes* sign1, uint8_t* key, bytes* external_aad) {
    /// Parse
    CborParser parser;
    CborValue val;
    cbor_parser_init(sign1->buf, sign1->len, 0, &parser, &val);

    CborTag tag;
    cbor_value_get_tag(&val, &tag);
    cbor_value_advance(&val);

    CborValue e;
    cbor_value_enter_container(&val, &e);

    bytes protected;
    cbor_value_dup_byte_string(&e, &protected.buf, &protected.len, &e);

    // Skip unprotected header
    cbor_value_advance(&e);

    bytes payload;
    cbor_value_dup_byte_string(&e, &payload.buf, &payload.len, &e);

    bytes signature;
    cbor_value_dup_byte_string(&e, &signature.buf, &signature.len, &e);

    /// Verify
    uint8_t to_verify[256];
    size_t to_verify_len;
    cose_sign1_structure("Signature1", &protected, external_aad, &payload, to_verify, sizeof(to_verify), &to_verify_len);

    // Compute digest
    uint8_t digest[DIGEST_SIZE];
    atcab_sha((uint16_t) to_verify_len, (const uint8_t*) to_verify, digest);

    bool verified = 0;
    atcab_verify_extern(digest, signature.buf, key, &verified);

    // Cleanup
    free(protected.buf);
    free(payload.buf);
    free(signature.buf);

    return verified;
}
