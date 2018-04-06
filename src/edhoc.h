#ifndef RS_HTTP_EDHOC_H
#define RS_HTTP_EDHOC_H

#include "cbor.h"
#include "types.h"
#include "cose.h"

typedef struct edhoc_msg_1 {
    uint8_t tag;
    bytes session_id;
    bytes nonce;
    bytes eph_key;
} edhoc_msg_1;

typedef struct edhoc_msg_2 {
    uint8_t tag;
    bytes session_id;
    bytes peer_session_id;
    bytes peer_nonce;
    bytes peer_key;
} edhoc_msg_2;

typedef struct msg_2_context {
    bytes shared_secret;
    bytes enc_key;
    bytes enc_iv;
    bytes message1;
} msg_2_context;

typedef struct edhoc_msg_3 {
    uint8_t tag;
    bytes peer_session_id;
    bytes cose_enc_3;
} edhoc_msg_3;

size_t edhoc_serialize_msg_2(edhoc_msg_2 *msg2, msg_2_context* context, unsigned char* buffer, size_t buf_size);

void edhoc_deserialize_msg1(edhoc_msg_1 *msg1, uint8_t* buffer, size_t len);
void edhoc_deserialize_msg3(edhoc_msg_3 *msg3, uint8_t* buffer, size_t len);

void edhoc_aad2(edhoc_msg_2 *msg2, bytes message1, uint8_t* out_hash);
void edhoc_msg2_sig_v(edhoc_msg_2 *msg2, uint8_t* aad2,
                      uint8_t* out, size_t out_size, size_t* out_len);

void edhoc_msg2_enc_0(edhoc_msg_2 *msg2, uint8_t *aad2, bytes *sig_v, bytes *key, bytes *iv,
                      uint8_t* out, size_t out_size, size_t* out_len);

void edhoc_aad3(edhoc_msg_3* msg3, bytes* message1, bytes* message2,
                uint8_t* out_hash);

void oscore_exchange_hash(bytes *msg1, bytes *msg2, bytes *msg3, uint8_t *out_hash);

#endif //RS_HTTP_EDHOC_H
