#include <stdio.h>

#include "mgos.h"
#include "cryptoauthlib.h"
#include "utils.h"

static void edhoc_handler_message_1(struct mg_connection* nc, int ev, void* ev_data) ;
static void edhoc_handler_message_3(struct mg_connection* nc, int ev, void* ev_data) ;

static const char *s_listening_address = "tcp://:8080";
uint8_t ID[64];

static void http_handler(struct mg_connection *nc, int ev, void *p, void *user_data)
{
    if (ev == MG_EV_HTTP_REQUEST)
    {
        struct http_message *hm = (struct http_message *)p;
       
        mg_send_head(nc, 200, hm->message.len, "Content-Type: text/plain");
        mg_printf(nc, "%.*s", (int)hm->message.len, hm->message.p);
    }
}

static void authz_info_handler(struct mg_connection* nc, int ev, void* ev_data, void *user_data) {
    // Parse HTTP Message
    //struct http_message *hm = (struct http_message *) ev_data;
    //struct mg_str data = hm->body;

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

    /*CborParser parser;
    CborValue ary;
    cbor_parser_init((void*)hm->body.p, hm->body.len, 0, &parser, &ary);

    CborValue elem;
    cbor_value_enter_container(&ary, &elem);

    uint64_t tag;
    cbor_value_get_uint64(&elem, &tag);*/
    uint64_t tag = 1;

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
    // Send response
    char response[64];
    int len = sprintf(response, "{\"edhoc\": %d}", 1);
    
    mg_send_head(nc, 200, len, "Content-Type: application/json");
    mg_send(nc, response, len);
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