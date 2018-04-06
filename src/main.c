#include <stdio.h>

#include "mgos.h"
#include "cryptoauthlib.h"
#include "utils.h"
#include "cwt.h"
#include "edhoc.h"
#include "cbor.h"

#define AUDIENCE "tempSensor0"

static void edhoc_handler_message_1(struct mg_connection* nc, int ev, void* ev_data) ;
static void edhoc_handler_message_3(struct mg_connection* nc, int ev, void* ev_data) ;

static const char *s_listening_address = "tcp://:8000";
static edhoc_server_session_state edhoc_state;
uint8_t ID[64];
uint8_t AS_ID[64] = {0x5a, 0xee, 0xc3, 0x1f, 0x9e, 0x64, 0xaa, 0xd4, 0x5a, 0xba, 0x2d, 0x36, 0x5e, 0x71, 0xe8, 0x4d, 0xee, 0x0d, 0xa3, 0x31, 0xba, 0xda, 0xb9, 0x11, 0x8a, 0x25, 0x31, 0x50, 0x1f, 0xd9, 0x86, 0x1d,
                     0x02, 0x7c, 0x99, 0x77, 0xca, 0x32, 0xd5, 0x44, 0xe6, 0x34, 0x26, 0x76, 0xef, 0x00, 0xfa, 0x43, 0x4b, 0x3a, 0xae, 0xd9, 0x9f, 0x48, 0x23, 0x75, 0x05, 0x17, 0xca, 0x33, 0x90, 0x37, 0x47, 0x53};

static void http_handler(struct mg_connection *nc, int ev, void *p, void *user_data)
{
    if (ev == MG_EV_HTTP_REQUEST)
    {
        struct http_message *hm = (struct http_message *)p;
       
        mg_send_head(nc, 200, hm->message.len, "Content-Type: text/plain");
        mg_printf(nc, "%.*s", (int)hm->message.len, hm->message.p);
    }
}

static size_t error_buffer(uint8_t* buf, size_t buf_len, char* text) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, buf_len, 0);

    CborEncoder map;
    cbor_encoder_create_map(&enc, &map, 1);

    cbor_encode_text_stringz(&map, "error");
    cbor_encode_text_stringz(&map, text);
    cbor_encoder_close_container(&enc, &map);

    return cbor_encoder_get_buffer_size(&enc, buf);
}

static void authz_info_handler(struct mg_connection* nc, int ev, void* ev_data, void *user_data) {
    // Parse HTTP Message
    struct http_message *hm = (struct http_message *) ev_data;
    struct mg_str data = hm->body;

    printf("Received CWT: ");
    phex((void*)data.p, data.len);

    // Parse CWT
    rs_cwt cwt;
    cwt_parse(&cwt, (void*) data.p, data.len);

    // Verify CWT
    bytes eaad = {.buf = NULL, .len = 0};

    int verified = cwt_verify(&cwt, eaad, AS_ID);

    if (verified != 1) {
        // Not authorized!
        uint8_t buf[128];
        size_t len = error_buffer(buf, sizeof(buf), "Signature could not be verified!");

        mg_send_head(nc, 401, (int64_t) len, "Content-Type: application/octet-stream");
        mg_send(nc, buf, (int) len);

        return;
    }

    // Parse Payload
    rs_payload payload;
    cwt_parse_payload(&cwt, &payload);

    // Verify audience
    if (strcmp(AUDIENCE, payload.aud) != 0) {
        uint8_t buf[128];
        size_t len = error_buffer(buf, sizeof(buf), "Audience mismatch!");

        mg_send_head(nc, 403, (int64_t) len, "Content-Type: application/octet-stream");
        mg_send(nc, buf, (int) len);

        return;
    }

    // Save PoP key
    cose_key cose_pop_key;
    cwt_parse_cose_key(&payload.cnf, &cose_pop_key);
    cwt_import_key(edhoc_state.pop_key, &cose_pop_key);

    // Send response
    mg_send_head(nc, 204, 0, "Content-Type: application/octet-stream");
}

static void temperature_handler(struct mg_connection* nc, int ev, void* ev_data, void *user_data) {
    int temperature = 30;

    char response[64];
    int len = sprintf(response, "{\"temperature\": %d}", temperature);

    // Send response
    mg_send_head(nc, 200, len, "Content-Type: application/json");
    mg_send(nc, response, len);
}

static void edhoc_handler(struct mg_connection* nc, int ev, void* ev_data, void *user_data) {
    struct http_message *hm = (struct http_message *) ev_data;

    char method[8];
    sprintf(method, "%.*s", hm->method.len, hm->method.p);

    if (strcmp(method, "POST") != 0) {
        mg_send_head(nc, 404, 0, NULL);
        return;
    }

    printf("Received EDHOC MSG: ");
    phex((void*)hm->body.p, hm->body.len);

    CborParser parser;
    CborValue ary;
    cbor_parser_init((void*)hm->body.p, hm->body.len, 0, &parser, &ary);

    CborValue elem;
    cbor_value_enter_container(&ary, &elem);

    uint64_t tag;
    cbor_value_get_uint64(&elem, &tag);

    switch (tag) {
        case 1:
            edhoc_handler_message_1(nc, ev, ev_data);
            break;
        case 3:
            edhoc_handler_message_3(nc, ev, ev_data);
            break;
        default: break;
    }
}

static void edhoc_handler_message_1(struct mg_connection* nc, int ev, void* ev_data) {
    struct http_message *hm = (struct http_message *) ev_data;

    // Read msg1
    edhoc_msg_1 msg1;
    edhoc_deserialize_msg1(&msg1, (void*)hm->body.p, hm->body.len);

    // Save message1 for later
    edhoc_state.message1.buf = malloc(hm->body.len);
    edhoc_state.message1.len = hm->body.len;
    memcpy(edhoc_state.message1.buf, hm->body.p, hm->body.len);

    // Generate random session id
    uint8_t session_id[32];
    atcab_random(session_id);
    edhoc_state.session_id = (bytes){ session_id, 2 };

    // Generate nonce
    uint8_t nonce[32];
    atcab_random(nonce);

    // Generate session key
    uint8_t session_key[64];
    atcab_genkey(1, session_key);

    // Compute shared secret
    cose_key cose_eph_key;
    cwt_parse_cose_key(&msg1.eph_key, &cose_eph_key);

    uint8_t eph_key[64];
    cwt_import_key(eph_key, &cose_eph_key);

    printf("Party Ephemeral Key is: {X:");
    for (int i = 0; i < 32; i++)
        printf("%02x", eph_key[i]);
    printf(", Y:");
    for (int i = 0; i < 32; i++)
        printf("%02x", eph_key[32 + i]);
    printf("}\n");

    uint8_t secret[32];
    atcab_ecdh(1, eph_key, secret);

    printf("Shared Secret: ");
    phex(secret, 32);

    // Save shared secret to state
    edhoc_state.shared_secret.buf = malloc(32);
    edhoc_state.shared_secret.len = 32;
    memcpy(edhoc_state.shared_secret.buf, secret, 32);

    // Encode session key
    uint8_t enc_sess_key[256];
    size_t n;
    cwt_encode_ecc_key(session_key, enc_sess_key, sizeof(enc_sess_key), &n);

    edhoc_msg_2 msg2 = {
            .tag = 2,
            .session_id = msg1.session_id,
            .peer_session_id = edhoc_state.session_id,
            .peer_nonce = {nonce, 8},
            .peer_key = {enc_sess_key, n},
    };

    msg_2_context ctx2 = {
            .shared_secret = (bytes) {secret, 32},
            .message1 = edhoc_state.message1
    };

    unsigned char msg_serialized[512];
    size_t len = edhoc_serialize_msg_2(&msg2, &ctx2, msg_serialized, sizeof(msg_serialized));

    edhoc_state.message2.buf = malloc(len);
    edhoc_state.message2.len = len;
    memcpy(edhoc_state.message2.buf, msg_serialized, len);

    printf("Sending EDHOC MSG: ");
    phex(msg_serialized, len);

    mg_send_head(nc, 200, len, "Content-Type: application/octet-stream");
    mg_send(nc, msg_serialized, len);
}

static void edhoc_handler_message_3(struct mg_connection* nc, int ev, void* ev_data) {
    // Send response
    char response[64];
    int len = sprintf(response, "{\"edhoc\": %d}", 3);
    
    mg_send_head(nc, 200, len, "Content-Type: application/json");
    mg_send(nc, response, len);
}

enum mgos_app_init_result mgos_app_init(void)
{
    printf("Hello, world!\n");
    struct mg_connection *nc;

    nc = mg_bind(mgos_get_mgr(), s_listening_address, http_handler, 0);
    if (nc == NULL)
    {
        LOG(LL_ERROR, ("Unable to start listener at %s", s_listening_address));
    }

    // Use HTTP Protocol
    mg_set_protocol_http_websocket(nc);

    // Setup endpoints
    mg_register_http_endpoint(nc, "/authz-info", authz_info_handler, 0);
    mg_register_http_endpoint(nc, "/.well-known/edhoc", edhoc_handler, 0);
    mg_register_http_endpoint(nc, "/temperature", temperature_handler, 0);

    // Generate ID
    atcab_genkey(0, ID);
    printf("RS public ID is: {X:");
    for (int i = 0; i < 32; i++)
        printf("%02x", ID[i]);
    printf(", Y:");
    for (int i = 0; i < 32; i++)
        printf("%02x", ID[32 + i]);
    printf("}\n");

    return MGOS_APP_INIT_SUCCESS;
}