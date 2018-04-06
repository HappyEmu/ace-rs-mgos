#ifndef RS_HTTP_UTILS_H
#define RS_HTTP_UTILS_H

#include <stdint.h>
#include <stddef.h>

void phex(uint8_t* ary, size_t len);

size_t buffer_to_hexstring(char** string, uint8_t* buffer, size_t buf_len);
size_t hexstring_to_buffer(uint8_t** buffer, char* string, size_t string_len);

#endif //RS_HTTP_UTILS_H