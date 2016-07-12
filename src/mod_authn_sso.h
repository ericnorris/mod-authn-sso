/**
 * mod_authn_sso.h
 *
 */

#ifndef MOD_AUTHN_SSO_H_
#define MOD_AUTHN_SSO_H_

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"

#include "ap_config.h"
#include "apr_strings.h"

#include <sodium.h>

/**
 * #defines
 */

#define MOD_AUTHN_SSO_AUTH_TYPE "mod_authn_sso"

/**
 * typedefs / structs
 */

typedef struct {
    char *context;
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    char *authn_url;
    char *cookie_name;
} authn_sso_config;

module authn_sso_module;

/**
 * Configuration functions
 */

void * create_authn_sso_config(apr_pool_t *pool, char *context);

void * merge_authn_sso_config(apr_pool_t *pool, void *parent, void *child);

const char * authn_sso_set_public_key(cmd_parms *cmd, void *config_param,
                                      const char *arg);

/**
 * Configuration definition
 */

const command_rec authn_sso_config_commands[] = {
    AP_INIT_TAKE1("AuthnSSOPublicKey", authn_sso_set_public_key,
        NULL, ACCESS_CONF,
        "public key used for validating SSO cookie"),

    AP_INIT_TAKE1("AuthnSSOUrl", ap_set_string_slot,
        (void *)APR_OFFSETOF(authn_sso_config, authn_url), OR_AUTHCFG,
        "URL to redirect to if authentication fails"),

    AP_INIT_TAKE1("AuthnSSOCookie", ap_set_string_slot,
        (void *)APR_OFFSETOF(authn_sso_config, cookie_name), OR_AUTHCFG,
        "name of required SSO cookie"),

    {NULL},
};

/**
 * Hook functions
 */

int authn_sso_post_config(apr_pool_t *config_pool, apr_pool_t *log_pool,
                          apr_pool_t *temp_pool, server_rec *server);

int authn_sso_check_authn(request_rec *request);

void authn_sso_register_hooks(apr_pool_t *pool);

#endif /* MOD_AUTHN_SSO_H_ */
