#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "ap_config.h"

#include <sodium.h>

module authn_sso_module;

#define MOD_AUTHN_SSO_AUTH_TYPE "mod_authn_sso"

void authn_sso_child_init(server_rec *s, apr_pool_t *pool) {
    sodium_init();
}

static int authn_sso_check(request_rec *request) {
    const char *current_auth;

    current_auth = ap_auth_type(request);

    if (!current_auth || strcasecmp(current_auth, MOD_AUTHN_SSO_AUTH_TYPE)) {
        return DECLINED;
    }

    apr_table_set(request->headers_out, "Location", "https://google.com");
    return HTTP_MOVED_TEMPORARILY;
}

static void authn_sso_register_hooks(apr_pool_t *pool) {
    ap_hook_child_init(authn_sso_child_init, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_check_user_id(authn_sso_check, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authn_sso_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                     /* create per-dir    config structures */
    NULL,                     /* merge  per-dir    config structures */
    NULL,                     /* create per-server config structures */
    NULL,                     /* merge  per-server config structures */
    NULL,                     /* table of config file commands       */
    authn_sso_register_hooks  /* register hooks                      */
};
