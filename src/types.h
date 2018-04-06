#ifndef RS_HTTP_RS_TYPES_H
#define RS_HTTP_RS_TYPES_H

#include <stdint.h>

typedef struct bytes {
    uint8_t * buf;
    size_t len;
} bytes;

#endif //RS_HTTP_RS_TYPES_H