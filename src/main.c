#include <stdio.h>

#include "mgos.h"

static const char *s_listening_address = "tcp://:8080";

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
    char response[64];
    int len = sprintf(response, "{\"edhoc\": %d}", 1);
    
    // Send response
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

    return MGOS_APP_INIT_SUCCESS;
}