#include <stdio.h>

#include "mgos.h"
#include "cryptoauthlib.h"
#include "utils.h"
#include "cwt.h"
#include "edhoc.h"
#include "cbor.h"
#include "mgos_dht.h"

#define AUDIENCE "tempSensor0"
#define SHA256_DIGEST_SIZE 32

static void edhoc_handler_message_1(struct mg_connection* nc, int ev, void* ev_data) ;
static void edhoc_handler_message_3(struct mg_connection* nc, int ev, void* ev_data) ;

static const char *s_listening_address = "tcp://:8000";

static edhoc_server_session_state edhoc_state;
static oscore_context context;
uint8_t state_mem[512 * 3];
static struct mgos_dht *s_dht = NULL;

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

static void compute_oscore_context() {
    /// Compute OSCORE Context
    uint8_t exchange_hash[SHA256_DIGEST_SIZE];
    oscore_exchange_hash(&edhoc_state.message1, &edhoc_state.message2, &edhoc_state.message3, exchange_hash);

    bytes ex_hash = {exchange_hash, SHA256_DIGEST_SIZE};

    // Master Secret
    uint8_t ci_secret[128];
    size_t ci_secret_len;
    cose_kdf_context("EDHOC OSCORE Master Secret", 16, &ex_hash, ci_secret, sizeof(ci_secret), &ci_secret_len);
    bytes b_ci_secret = {ci_secret, ci_secret_len};

    // Master Salt
    uint8_t ci_salt[128];
    size_t ci_salt_len;
    cose_kdf_context("EDHOC OSCORE Master Salt", 8, &ex_hash, ci_salt, sizeof(ci_salt), &ci_salt_len);
    bytes b_ci_salt = {ci_salt, ci_salt_len};
    
    derive_key(&edhoc_state.shared_secret, &b_ci_secret, context.master_secret, 16);
    derive_key(&edhoc_state.shared_secret, &b_ci_salt, context.master_salt, 8);
    
    printf("MASTER SECRET: ");
    phex(context.master_secret, 16);
    printf("MASTER SALT: ");
    phex(context.master_salt, 8);
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

    int verified = cwt_verify(&cwt, &eaad, AS_ID);

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

    // Free resources
    free(payload.cnf.buf);
    free(payload.aud);
    free(cose_pop_key.kid.buf);
    free(cose_pop_key.x.buf);
    free(cose_pop_key.y.buf);

    // Send response
    mg_send_head(nc, 201, 0, "Content-Type: application/octet-stream");
}

static void temperature_handler(struct mg_connection* nc, int ev, void* ev_data, void *user_data) {
    int temperature = (int) mgos_dht_get_temp(s_dht);
    int humidity = (int) mgos_dht_get_humidity(s_dht);

    printf("Humidity: %d", humidity);
    printf("Temperature: %d", temperature);

    /// Create Response
    uint8_t response[128];
    CborEncoder enc;
    cbor_encoder_init(&enc, response, sizeof(response), 0);

    CborEncoder map;
    cbor_encoder_create_map(&enc, &map, 2);
    cbor_encode_text_stringz(&map, "temperature");
    cbor_encode_int(&map, temperature);
    cbor_encode_text_stringz(&map, "humidity");
    cbor_encode_int(&map, humidity);
    cbor_encoder_close_container(&enc, &map);

    size_t len = cbor_encoder_get_buffer_size(&enc, response);

    /// Encrypt response
    uint8_t* prot_header;
    size_t prot_len = hexstring_to_buffer(&prot_header, "a1010c", strlen("a1010c"));
    bytes b_prot_header = {prot_header, prot_len};

    cose_encrypt0 enc_response = {
        .plaintext = (bytes) {response, len},
        .protected_header = b_prot_header,
        .external_aad = {NULL, 0}
    };

    uint8_t res[256];
    size_t res_len;
    cose_encode_encrypted(&enc_response, context.master_secret, context.master_salt, 7, res, sizeof(res), &res_len);

    mg_send_head(nc, 200, (int64_t) res_len, "Content-Type: application/octet-stream");
    mg_send(nc, res, (int) res_len);

    free(prot_header);
}

static void set_led_handler(struct mg_connection* nc, int ev, void* ev_data, void *user_data) {
    struct http_message *hm = (struct http_message *) ev_data;
    bytes ciphertext = {(void*)hm->body.p, hm->body.len};
    bytes aad = {NULL, 0};

    // Decrypt payload
    uint8_t payload[32];
    size_t payload_length = 0;
    cose_decrypt_enc0(&ciphertext, context.master_secret, context.master_salt, 7, &aad, payload, sizeof(payload), &payload_length);

    // Parse payload
    CborParser parser;
    CborValue val;
    cbor_parser_init(payload, payload_length, 0, &parser, &val);

    int led_value = 0;
    cbor_value_get_int(&val, &led_value);

    printf("Setting LED value to %d\n", led_value);

    // Write new value to LED
    mgos_gpio_write(25, led_value);

    // Respond
    mg_send_head(nc, 204, 0, NULL);
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
            compute_oscore_context();
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

    edhoc_state.message2.len = len;
    memcpy(edhoc_state.message2.buf, msg_serialized, len);

    printf("Sending EDHOC MSG: ");
    phex(msg_serialized, len);

    // Cleanup
    free(msg1.session_id.buf);
    free(msg1.nonce.buf);
    free(msg1.eph_key.buf);

    mg_send_head(nc, 200, len, "Content-Type: application/octet-stream");
    mg_send(nc, msg_serialized, len);
}

static void edhoc_handler_message_3(struct mg_connection* nc, int ev, void* ev_data) {
    struct http_message *hm = (struct http_message *) ev_data;

    // Save message3 for later
    edhoc_state.message3.len = hm->body.len;
    memcpy(edhoc_state.message3.buf, hm->body.p, hm->body.len);

    // Deserialize msg3
    edhoc_msg_3 msg3;
    edhoc_deserialize_msg3(&msg3, (void*)hm->body.p, hm->body.len);

    // Compute aad3
    uint8_t aad3[SHA256_DIGEST_SIZE];
    edhoc_aad3(&msg3, &edhoc_state.message1, &edhoc_state.message2, aad3);

    // Derive k3, iv3
    bytes other = {aad3, SHA256_DIGEST_SIZE};

    uint8_t context_info_k3[128];
    size_t ci_k3_len;
    cose_kdf_context("AES-CCM-64-64-128", 16, &other, context_info_k3, sizeof(context_info_k3), &ci_k3_len);

    uint8_t context_info_iv3[128];
    size_t ci_iv3_len;
    cose_kdf_context("IV-Generation", 13, &other, context_info_iv3, sizeof(context_info_iv3), &ci_iv3_len);

    bytes b_ci_k3 = {context_info_k3, ci_k3_len};
    bytes b_ci_iv3 = {context_info_iv3, ci_iv3_len};

    uint8_t k3[16];
    derive_key(&edhoc_state.shared_secret, &b_ci_k3, k3, sizeof(k3));

    uint8_t iv3[13];
    derive_key(&edhoc_state.shared_secret, &b_ci_iv3, iv3, sizeof(iv3));

    // printf("AAD3: ");
    // phex(aad3, SHA256_DIGEST_SIZE);
    printf("K3: ");
    phex(k3, 16);
    printf("IV3: ");
    phex(iv3, 13);

    bytes b_aad3 = {aad3, SHA256_DIGEST_SIZE};

    uint8_t sig_u[256];
    size_t sig_u_len;
    cose_decrypt_enc0(&msg3.cose_enc_3, k3, iv3, 13, &b_aad3, sig_u, sizeof(sig_u), &sig_u_len);

    bytes b_sig_u = {sig_u, sig_u_len};
    int verified = cose_verify_sign1(&b_sig_u, edhoc_state.pop_key, &b_aad3);

    if (verified != 1) {
        // Not authorized!
        uint8_t buf[128];
        size_t len = error_buffer(buf, sizeof(buf), "You are not the one who uploaded the token!");

        mg_send_head(nc, 401, (int64_t) len, "Content-Type: application/octet-stream");
        mg_send(nc, buf, (int) len);

        return;
    }

    // Cleanup
    free(msg3.peer_session_id.buf);
    free(msg3.cose_enc_3.buf);

    // Send response (OK)
    uint8_t *buf;
    size_t buf_len = hexstring_to_buffer(&buf, "81624f4b", strlen("81624f4b"));
    mg_send_head(nc, 201, (int64_t) buf_len, "Content-Type: application/octet-stream");
    mg_send(nc, buf, (int) buf_len);
    
    free(buf);
}

enum mgos_app_init_result mgos_app_init(void)
{
    printf("App init...\n");
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
    mg_register_http_endpoint(nc, "/led", set_led_handler, 0);

    // Allocate space for stored messages
    edhoc_state.message1.buf = state_mem;
    edhoc_state.message2.buf = state_mem + 512;
    edhoc_state.message3.buf = state_mem + 1024; 
    edhoc_state.shared_secret.buf = malloc(32);
    edhoc_state.shared_secret.len = 32;

    // Generate ID
    atcab_get_pubkey(0, ID);
    printf("RS public ID is: {X:");
    for (int i = 0; i < 32; i++)
        printf("%02x", ID[i]);
    printf(", Y:");
    for (int i = 0; i < 32; i++)
        printf("%02x", ID[32 + i]);
    printf("}\n");

    // Print slot config
    /*printf("Key Slot: ");
    bool locked = 0;
    for (int i = 0; i < 16; i++) {
        atcab_is_slot_locked(i, &locked);
        printf("Slot %i: %i\n", i, locked);
    }
    printf("\n");*/

    // Configure LED actuator
    mgos_gpio_set_mode(25, MGOS_GPIO_MODE_OUTPUT);
    mgos_gpio_write(25, 0);

    // Initialize Temperature sensor
    if ((s_dht = mgos_dht_create(5, DHT22)) == NULL) 
        return MGOS_APP_INIT_ERROR;

    return MGOS_APP_INIT_SUCCESS;
}