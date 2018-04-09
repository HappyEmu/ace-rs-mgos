#ifndef RS_HTTP_CWT_H
#define RS_HTTP_CWT_H

#include "cbor.h"
#include "types.h"

typedef struct rs_key {
    char* x;
    char* y;
    char* d;
} rs_key;

typedef struct cose_key {
    bytes kid;
    uint8_t kty;
    uint8_t crv;
    bytes x;
    bytes y;
} cose_key;

typedef struct rs_cwt {
    CborValue h_protected;
    CborValue h_unprotected;
    CborValue payload;
    CborValue signature;
} rs_cwt;

typedef struct rs_payload {
    char* iss;
    int iat;
    int exp;
    int cti;
    char* scope;
    char* aud;
    bytes cnf;
} rs_payload;

void cwt_parse(rs_cwt* cwt, uint8_t* encoded, size_t len);
int cwt_verify(rs_cwt* cwt, bytes *eaad, uint8_t *key);
void cwt_parse_payload(rs_cwt* cwt, rs_payload*);
void cwt_parse_cose_key(bytes* encoded, cose_key* out);
void cwt_encode_cose_key(cose_key* key, uint8_t* buffer, size_t buf_size, size_t* len);
void cwt_encode_ecc_key(uint8_t* key, uint8_t* buffer, size_t buf_size, size_t* len);
void cwt_import_key(uint8_t* key, cose_key* cose);


#endif //RS_HTTP_CWT_H