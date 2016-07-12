#include "mod_authn_sso.h"

// Initialization

/**
 *  Declare the module (apache2-style) and configure the various hook and
 *  configuration loading code.
 */
module AP_MODULE_DECLARE_DATA authn_sso_module = {
    STANDARD20_MODULE_STUFF,
    create_authn_sso_config,   // create per-dir config structures
    merge_authn_sso_config,    // merge  per-dir config structures
    NULL,                      // create per-server config structures
    NULL,                      // merge  per-server config structures
    authn_sso_config_commands, // table of config file commands
    authn_sso_register_hooks   // register hooks
};

/**
 * Register the apache hooks used by this module.
 *
 * @param apr_pool_t *pool an apache memory pool
 */
void authn_sso_register_hooks(apr_pool_t *pool) {
    ap_hook_post_config(authn_sso_post_config, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_check_authn(authn_sso_check_authn, NULL, NULL, APR_HOOK_FIRST,
                        AP_AUTH_INTERNAL_PER_CONF);
}

// Configuration

/**
 * Allocate a brand-new authn_sso_config struct associated with the given pool.
 *
 * @param apr_pool_t *pool    an apache memory pool
 * @param char       *context the directory this config is associated with
 *
 * @return authn_sso_config the newly allocated configuration, with defaults
 */
void * create_authn_sso_config(apr_pool_t *pool, char *context) {
    authn_sso_config *config = apr_pcalloc(pool, sizeof(authn_sso_config));

    config->context = context;

    return config;
}

/**
 * Merge a parent and child directory configuration.
 *
 * @param apr_pool_t *pool   an apache memory pool
 * @param void       *parent the parent directory config
 * @param void       *child  the child directory config
 */
void * merge_authn_sso_config(apr_pool_t *pool, void *parent, void *child) {

    authn_sso_config *parent_config = (authn_sso_config *)parent;
    authn_sso_config *child_config  = (authn_sso_config *)child;
    authn_sso_config *merged_config = create_authn_sso_config(
        pool,
        child_config->context
    );

    strncpy(
        (char *)&merged_config->public_key,
        (char *)(child_config->public_key ?
            &child_config->public_key :
            &parent_config->public_key),
        crypto_sign_PUBLICKEYBYTES
    );

    merged_config->authn_url = (child_config->authn_url) ?
            child_config->authn_url : parent_config->authn_url;

    merged_config->cookie_name = (child_config->cookie_name) ?
            child_config->cookie_name : parent_config->cookie_name;

    return merged_config;
}

/**
 * Sets the public key to the hex decoded value specified in the config.
 *
 * @param cmd_parms  *cmd
 * @param void       *config_param the authn_sso_config to modify
 * @param const char *arg          a hex encoded public key
 */
const char * authn_sso_set_public_key(cmd_parms *cmd, void *config_param,
                                      const char *arg) {

    authn_sso_config *config;
    unsigned char *public_key_ptr;
    int hex2bin_result;

    config         = (authn_sso_config*)config_param;
    public_key_ptr = config->public_key;

    hex2bin_result = sodium_hex2bin(public_key_ptr, crypto_sign_PUBLICKEYBYTES,
                                    arg, strlen(arg), NULL, NULL, NULL);

    if (hex2bin_result == -1) {
        return apr_psprintf(cmd->pool, "unable to hex decode public key '%s'",
                            arg);
    }

    return NULL;
}

/**
 * Handle any necessary initialization after the configuration has been
 * processed.
 *
 * @param apr_pool_t *config_pool
 * @param apr_pool_t *log_pool
 * @param apr_pool_t *temp_pool
 * @param server_rec *server
 *
 * @return int OK if success, any other value if error
 */
int authn_sso_post_config(apr_pool_t *config_pool, apr_pool_t *log_pool,
                          apr_pool_t *temp_pool, server_rec *server) {

    if (sodium_init() == -1) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

/**
 * Check if the given request is authenticated.
 *
 * This function will return DECLINED if not applicable, OK if authenticated,
 * and will redirect to the specified SSO URL if necessary.
 *
 * @param request_rec *request the request to check
 *
 * @return int
 */
int authn_sso_check_authn(request_rec *request) {
    const char *current_auth;

    current_auth = ap_auth_type(request);

    if (!current_auth || strcasecmp(current_auth, MOD_AUTHN_SSO_AUTH_TYPE)) {
        return DECLINED;
    }

    authn_sso_config *config = (authn_sso_config *)ap_get_module_config(
        request->per_dir_config,
        &authn_sso_module);

    // TODO check for cookie and validate using public key

    ap_log_error(
        APLOG_MARK, APLOG_ERR, APR_SUCCESS,
        request->server,
        "public_key: %s", config->public_key
    );

    //apr_table_set(request->headers_out, "Location", "https://google.com");
    return HTTP_MOVED_TEMPORARILY;
}




