#ifndef RS_HTTP_RS_TYPES_H
#define RS_HTTP_RS_TYPES_H

#include <stdint.h>
#include <stddef.h>

typedef struct bytes {
    uint8_t * buf;
    size_t len;
} bytes;

typedef struct edhoc_server_session_state {
    bytes session_id;
    uint8_t pop_key[64];
    bytes shared_secret;
    bytes message1;
    bytes message2;
    bytes message3;
} edhoc_server_session_state;

typedef struct oscore_context {
    uint8_t master_secret[16];
    uint8_t master_salt[8];
} oscore_context;

#endif //RS_HTTP_RS_TYPES_H