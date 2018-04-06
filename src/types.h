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
    uint8_t *pop_key;
    bytes shared_secret;
    bytes message1;
    bytes message2;
    bytes message3;
} edhoc_server_session_state;

#endif //RS_HTTP_RS_TYPES_H