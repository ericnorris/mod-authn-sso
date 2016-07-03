#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "ap_config.h"

#include <sodium.h>

module authn_sso_module;

#define MOD_AUTHN_SSO_AUTH_TYPE "mod_authn_sso"

int authn_sso_post_config(apr_pool_t *config_pool, apr_pool_t *log_pool,
                          apr_pool_t *temp_pool, server_rec *s) {

    if (sodium_init() == -1) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

static int authn_sso_check_authn(request_rec *request) {
    const char *current_auth;

    current_auth = ap_auth_type(request);

    if (!current_auth || strcasecmp(current_auth, MOD_AUTHN_SSO_AUTH_TYPE)) {
        return DECLINED;
    }

    apr_table_set(request->headers_out, "Location", "https://google.com");
    return HTTP_MOVED_TEMPORARILY;
}

static void authn_sso_register_hooks(apr_pool_t *pool) {
    ap_hook_post_config(authn_sso_post_config, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_check_authn(authn_sso_check_authn, NULL, NULL, APR_HOOK_FIRST,
                        AP_AUTH_INTERNAL_PER_CONF);
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
