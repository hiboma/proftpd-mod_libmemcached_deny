#include "conf.h"
#include "libmemcached/memcached.h"
#include "libmemcached/memcached_util.h"

#include <stdbool.h>
#include <utmp.h>

module libmemcached_deny_module;

#define MODULE_NAME libmemcached_deny_module.name

/* max account length + max IP length (255.255.255.255) + \0 */
#define _MAX_KEY_LENGTH UT_NAMESIZE + 15 + 1;

/* ro */
static const int MAX_KEY_LENGTH = _MAX_KEY_LENGTH;

/* rw */
static bool is_set_server = false;
static memcached_st *memcached_deny_mmc = NULL;

#ifdef DEBUG
static int walk_table(const void *key_data,
                      void *value_data,
                      size_t value_datasz,
                      void *user_data) {
    pr_log_debug(DEBUG2, "%s %s => %s\n", MODULE_NAME, (char *)key_data, (char *)value_datasz);
    return 0;
}
#endif

static void lmd_postparse_ev(const void *event_data, void *user_data) {
    memcached_stat_st *unused;
    memcached_return_t rc;

    unused = memcached_stat(memcached_deny_mmc, NULL, &rc);
    if(rc != MEMCACHED_SUCCESS) {
        pr_log_pri(PR_LOG_WARNING,
            "%s: Failed connect to memcached."
            "Please check memcached is alive", MODULE_NAME);

        if(SERVER_INETD == ServerType)
            exit(1);
    }
}

static int lmd_init(void) {
    memcached_deny_mmc = memcached_create(NULL);
    if(!memcached_deny_mmc) {
        pr_log_pri(PR_LOG_ERR, "Fatal %s: Out of memory", MODULE_NAME);
        exit(1);
    }
    pr_event_register(&libmemcached_deny_module,
        "core.postparse", lmd_postparse_ev, NULL);
    return 0;
}

MODRET add_lmd_explicit_user(cmd_rec *cmd) {
    config_rec *c;
    int i;
    pr_table_t *explicit_users;

    if(cmd->argc < 2)
        CONF_ERROR(cmd, "missing argument");

    CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL);

    /* argv => LMDUser nobody nobody1 nobody2 */
    c = find_config(main_server->conf, CONF_PARAM, "LMDUser", FALSE);
    if(c && c->argv[0]) {
        explicit_users = c->argv[0];
    } else {
        c = add_config_param(cmd->argv[0], 0, NULL);
        c->argv[0] = explicit_users = pr_table_alloc(main_server->pool, 0);
    }

    for(i=1; i < cmd->argc; i++) {
        const char *account = pstrdup(main_server->pool, cmd->argv[i]);
        if(pr_table_exists(explicit_users, account) > 0) {
            pr_log_debug(DEBUG2,
                "%s: %s is already registerd", MODULE_NAME, account);
            continue;
        }

        if(pr_table_add_dup(explicit_users, account, "y", 0) < 0){
            pr_log_pri(PR_LOG_ERR,
                "%s: failed pr_table_add_dup(): %s",
                 MODULE_NAME, strerror(errno));
            exit(1);
        }
        pr_log_debug(DEBUG2,
            "%s: add LMDUser[%d] %s", MODULE_NAME, i, account);
    }

    return PR_HANDLED(cmd);
}

MODRET add_lmd_explicit_user_regex(cmd_rec *cmd) {
    array_header *list;
    regex_t *preg;
    int i, res;
    config_rec *c;

    if(cmd->argc < 2)
        CONF_ERROR(cmd, "missing argument");
    CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL);

    /* argv => LMDUserRegex ^test */
    c = find_config(cmd->server->conf, CONF_PARAM, "LMDUserRegex", FALSE);
    if(c && c->argv[0]) {
        list = c->argv[0];
    } else {
        c = add_config_param(cmd->argv[0], 0, NULL);
        c->argv[0] = list = make_array(cmd->server->pool, 0, sizeof(regex_t *));
    }

    for(i=1; i < cmd->argc; i++) {
        preg = pr_regexp_alloc();
        res  = regcomp(preg, cmd->argv[i], REG_NOSUB);
        if (res != 0) {
            char errstr[200] = {'\0'};
            regerror(res, preg, errstr, sizeof(errstr));
            pr_regexp_free(preg);
            CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[i], "' failed "
               "regex compilation: ", errstr, NULL));
        }
        *((regex_t **) push_array(list)) = preg;
        pr_log_debug(DEBUG2,
            "%s: add LMDUserRegex[%d] %s", MODULE_NAME, i, cmd->argv[i]);
    }

    return PR_HANDLED(cmd);
}

MODRET add_lmd_allow_from(cmd_rec *cmd) {
    config_rec *c;
    int i;
    pr_table_t *allowed_ips;

    if(cmd->argc < 2 )
        CONF_ERROR(cmd, "argument missing");

    CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL);

    /* argv => LMDMemcachedHost 127.0.0.1 192.168.0.1 ... */
    c = find_config(main_server->conf, CONF_PARAM, "LMDAllowFrom", FALSE);
    if(c && c->argv[0]) {
        allowed_ips = c->argv[0];
    } else {
        c = add_config_param(cmd->argv[0], 0, NULL);
        c->argv[0] = allowed_ips = pr_table_alloc(main_server->pool, 0);
    }

    for(i=1; i < cmd->argc; i++) {
        /*
         *ここでpstrdupしておかないと、１度ログインするとpoolに回収され
         * allowed_ipsのキー一覧 から消えてバグの元になる
         */
        const char *ip = pstrdup(main_server->pool, cmd->argv[i]);
        if(pr_table_exists(allowed_ips, ip) > 0) {
            pr_log_debug(DEBUG2,
                "%s: %s is already registerd", MODULE_NAME, ip);
            continue;
        }

        if(pr_table_add_dup(allowed_ips, ip, "y", 0) < 0){
            pr_log_pri(PR_LOG_ERR,
              "%s: failed pr_table_add_dup(): %s",
              MODULE_NAME, strerror(errno));
            exit(1);
        }
        pr_log_debug(DEBUG2,
            "%s: add LMDAllowFrom[%d] %s", MODULE_NAME, i, ip);
    }

    return PR_HANDLED(cmd);
}

MODRET add_lmd_memcached_host(cmd_rec *cmd) {
    int i;
    memcached_return rc;
    memcached_server_st *server = NULL;

    if(cmd->argc < 2 )
        CONF_ERROR(cmd, "argument missing");

    CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL);

    /* NOTICE: i = 1 */
    for(i=1; i < cmd->argc; i++) {
        const char *arg = cmd->argv[i];
        server = memcached_servers_parse(arg);
        rc = memcached_server_push(memcached_deny_mmc, server);
        if(rc != MEMCACHED_SUCCESS){
            pr_log_auth(PR_LOG_ERR,
              "Fatal %s: failed memcached_strerror(): %s",
              MODULE_NAME, memcached_strerror(memcached_deny_mmc, rc));
            exit(1);
        }
        pr_log_debug(DEBUG2,
            "%s: add memcached server %s", MODULE_NAME, arg);
    }
    is_set_server = true;
    return PR_HANDLED(cmd);
}

/* todo */
static int lmd_timeout_callback(CALLBACK_FRAME) {
    pr_log_auth(PR_LOG_WARNING,
        "%s: memcached timeout", MODULE_NAME);
    return 0;
}

/*
 * memcached has
 *
 *     <account>@<proftpd IP> : <client IP>
 *     <account>@<proftpd IP> : <REMOTE_HOST>
 *     <account>@<proftpd IP> : <client IP>\t<REMOTE_HOST> ...
 */
static bool is_cache_exits(memcached_st *mmc,
                           const char *key,
                           const char *remote_ip,
                           const char *remote_host) {
    int timer_id;
    memcached_return rc;
    const char *ip_or_hostname;
    char *cached_value;
    size_t value_len;
    uint32_t flag;

    /* todo */
    timer_id = pr_timer_add(1, -1, NULL, lmd_timeout_callback, "memcached_get");
    cached_value = memcached_get(mmc, key, strlen(key), &value_len, &flag, &rc);
    pr_timer_remove(timer_id, NULL);

    /* no cache */
    if(MEMCACHED_NOTFOUND == rc)
        return false;

    /* failed by other reason */
    if(MEMCACHED_SUCCESS  != rc &&
       MEMCACHED_NOTFOUND != rc) {
        pr_log_auth(PR_LOG_ERR,
            "%s: failed memcached_get() %s",
           MODULE_NAME, memcached_strerror(mmc, rc));
        return false;
    }

    /* cache not fond */
    if(NULL == cached_value)
        return false;

    /* something wrong */
    if(0 == value_len)
        return false;

    while((ip_or_hostname = pr_str_get_token(&cached_value, "\t")) != NULL) {
        /* compare memacched IP with client hostname */
        if(remote_host && 0 == strcmp(ip_or_hostname, remote_host)) {
            pr_log_debug(DEBUG2,
               "%s: memcached hostname '%s' matched with remote host '%s'",
                MODULE_NAME,  ip_or_hostname, remote_host);
            return true;
        }
        /* compare memacched IP with client IP */
        if(0 == strcmp(ip_or_hostname, remote_ip)) {
            pr_log_debug(DEBUG2,
               "%s: memcached IP '%s' matched with remote IP '%s'",
                MODULE_NAME,  ip_or_hostname, remote_ip);
            return true;
        }
    }

    return false;
}

static bool is_explicit_mode_user(cmd_rec *cmd, const char *account) {
    config_rec *c;

    /* ハッシュテーブルにアカウントがあるか否か */
    c = find_config(cmd->server->conf, CONF_PARAM, "LMDUser", FALSE);
    if(c && c->argv[0]) {
        pr_table_t *explicit_users = c->argv[0];
        if(pr_table_exists(explicit_users, account) > 0 ) {
            pr_log_debug(DEBUG2,
                "%s: %s is found in LMDUser", MODULE_NAME, account);
            return true;
        }
    }

    /* 正規表現にマッチするか否か */
    c = find_config(cmd->server->conf, CONF_PARAM, "LMDUserRegex", FALSE);
    if(c && c->argv[0]) {
        int i;
        array_header *regex_list = c->argv[0];
        regex_t ** elts = regex_list->elts;

        for (i = 0; i < regex_list->nelts; i++) {
            regex_t *preg = elts[i];
            if(regexec(preg, account, 0, NULL, 0) == 0) {
                pr_log_debug(DEBUG2,
                    "%s: %s is found in LMDUserRegex", MODULE_NAME, account);
                return true;
            }
        }
    }

    return false;
}

static bool is_explicitly_denied(memcached_st *mmc, const char *key) {
    memcached_return rc;
    char *cached_value;
    size_t value_len;
    uint32_t flag;
    bool res = false;

    cached_value = memcached_get(mmc, key, strlen(key), &value_len, &flag, &rc);

    switch(rc) {
    case MEMCACHED_SUCCESS:
        if((NULL == cached_value) || (0 == value_len)){
            break;
        }
        if(strcasecmp(cached_value, "deny") == 0) {
            res = true;
        }
    case MEMCACHED_NOTFOUND:
       break;
    default:
        pr_log_auth(PR_LOG_WARNING, "%s: failed memcached_get() %s",
            MODULE_NAME, memcached_strerror(mmc, rc));
    }

    return res;
}

static bool is_allowed_from(cmd_rec *cmd,
                            const char *remote_ip,
                            const char *remote_host) {
    config_rec *c;
    pr_table_t *allowed_ips;

    c = find_config(cmd->server->conf, CONF_PARAM, "LMDAllowFrom", FALSE);
    if(NULL == c)
        return false;

    allowed_ips = c->argv[0];
    if(NULL == allowed_ips) {
        pr_log_auth(PR_LOG_ERR,
          "%s: pr_table_t is NULL. something fatal", MODULE_NAME);
        return false;
    }

#ifdef DEBUG
    pr_table_do(allowed_ips, walk_table, NULL, 0);
#endif

    if(pr_table_exists(allowed_ips, remote_host) > 0) {
         pr_log_auth(PR_LOG_NOTICE,
             "%s: hostname '%s' found in LMDAllowFrom. Skip last process", MODULE_NAME, remote_host);
         return true;
    }

    if(pr_table_exists(allowed_ips, remote_ip) > 0) {
         pr_log_auth(PR_LOG_NOTICE,
             "%s: IP '%s' found in LMDAllowFrom. Skip last process", MODULE_NAME, remote_ip);
         return true;
    }

    return false;
}

MODRET lmd_deny_post_pass(cmd_rec *cmd) {
    /*
      mod_authを通過するまでは session.userは空の様子
      const char *account  = session.user;
    */
    const char *key;
    const char *account   = NULL; 
    const char *remote_ip = NULL;
    const char *local_ip = NULL;
    const char *remote_host = NULL;

    if(false == is_set_server) {
        pr_log_auth(PR_LOG_ERR, "%s: memcached_server not set", MODULE_NAME);
        pr_response_send(R_530, _("Login denyied (server error)"));
        return PR_DECLINED(cmd);
    }

    account = get_param_ptr(main_server->conf, C_USER, FALSE);
    if(NULL == account) {
        pr_log_auth(PR_LOG_ERR, "unknown account.");
        pr_response_send(R_530, _("Login denyied (server error)"));
        end_login(0);
    }

    /* key is <account>@<proftpd IP> */
    local_ip  = pr_netaddr_get_ipstr(pr_netaddr_get_sess_local_addr());
    key = pstrcat(cmd->tmp_pool, account, "@", local_ip, NULL);

    if(is_explicitly_denied(memcached_deny_mmc, key) == true) {
        pr_log_auth(PR_LOG_INFO,
            "%s: cache 'deny' found for '%s'", MODULE_NAME, key);
        pr_response_send(R_530, _("Login denyied"));
        end_login(0);
    }

    if(is_explicit_mode_user(cmd, account) == false) {
        pr_log_auth(PR_LOG_NOTICE,
           "%s: %s is not registerd as an explicit mode user. Skip last process", MODULE_NAME, account);
        return PR_DECLINED(cmd);
    }

    /* return IP unless found hostname */
    remote_host = pr_netaddr_get_sess_remote_name();
    remote_ip = pr_netaddr_get_ipstr(pr_netaddr_get_sess_remote_addr());

    /* allow explicily */
    if(is_allowed_from(cmd, remote_ip, remote_host) == true) {
        return PR_DECLINED(cmd);
    }

    pr_log_debug(DEBUG5,
      "%s: '%s' not found in Allowed IP", MODULE_NAME, remote_ip);

    if(is_cache_exits(memcached_deny_mmc,key, remote_ip, remote_host) == false) {
        pr_log_auth(PR_LOG_NOTICE,
            "%s: memcached IP not found for '%s', Denied", MODULE_NAME, key);
        pr_response_send(R_530, _("Login denyied (cache is expired)"));
        end_login(0);
    }

    pr_log_debug(DEBUG2,
        "%s: cache found. '%s' is allowed to auth", MODULE_NAME, key);

    return PR_DECLINED(cmd);
}

static conftable lmd_deny_conftab[] = {
    { "LMDUser",          add_lmd_explicit_user,       NULL },
    { "LMDUserRegex",     add_lmd_explicit_user_regex, NULL },
    { "LMDAllowFrom",     add_lmd_allow_from,          NULL },
    { "LMDMemcachedHost", add_lmd_memcached_host,      NULL },
    { NULL }
};
 
static cmdtable lmd_deny_cmdtab[] = {
    { POST_CMD, C_USER, G_NONE, lmd_deny_post_pass, FALSE, FALSE, CL_AUTH },
    { 0, NULL }
};

module libmemcached_deny_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "libmemcached_deny",

  /* Module configuration directive table */
  lmd_deny_conftab,

  /* Module command handler table */
  lmd_deny_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  lmd_init ,

  /* Session initialization function */
  NULL,
};
