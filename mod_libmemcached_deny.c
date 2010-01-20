#include "conf.h"
#include "privs.h"
#include "libmemcached/memcached.h"
#include "libmemcached/memcached_util.h"

#include <stdbool.h>
#include <utmp.h>

static const char * const MODULE_NAME = "mod_libmemcached_deny";

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

static int libmemcached_deny_init(void) {
    memcached_deny_mmc = memcached_create(NULL);
    if(!memcached_deny_mmc) {
        pr_log_pri(PR_LOG_ERR, "Fatal %s: Out of memory", MODULE_NAME);
        exit(1);
    }
    return 0;
}

MODRET add_libmemcached_explicit_user(cmd_rec *cmd) {
    config_rec *c;
    int i;
    pr_table_t *explicit_users;

    /* check command context */
    CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL);

    /* argv => LMDExplicitUser nobody nobody1 nobody2 */
    c = find_config(main_server->conf, CONF_PARAM, "LMDExplicitModeUser", FALSE);
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
                     "%s: add LMDExplicitModeUser[%d] %s", MODULE_NAME, i, account);
    }

    return PR_HANDLED(cmd);
}

MODRET set_libmemcached_explicit_mode(cmd_rec *cmd) {
    int boolean = -1;
    config_rec *c;

    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL);

    boolean = get_boolean(cmd, 1);
    if (boolean == -1)
        CONF_ERROR(cmd, "expected boolean parameter");

    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(int));
    *((int *) c->argv[0]) = boolean;

    pr_log_debug(DEBUG2,
                 "%s: LMDExplicitMode is %d", MODULE_NAME, boolean);

    return PR_HANDLED(cmd);
}

MODRET add_libmemcached_deny_allow_from(cmd_rec *cmd) {
    config_rec *c;
    int i;
    pr_table_t *allowed_ips;

    /* check command context */
    CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL);

    /* argv => LibMemcachedDenyServer 127.0.0.1 192.168.0.1 ... */
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
                     "%s: add LibMemcachedDenyAllowFrom[%d] %s", MODULE_NAME, i, ip);
    }

    return PR_HANDLED(cmd);
}

MODRET set_memcached_memcached_host(cmd_rec *cmd) {

    int i;
    memcached_return rc;
    memcached_server_st *server = NULL;

    /* check command context */
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
static int libmemcached_deny_timeout_callback(CALLBACK_FRAME) {
    pr_log_auth(PR_LOG_WARNING,
                "%s: memcached timeout", MODULE_NAME);
    return 0;
}

/*
 * memcached has
 *     <account>@<proftpd IP> : <client IP>
 */
static bool libmemcached_deny_cache_exits(memcached_st *mmc,
                                       const char *key,
                                       const char *remote_ip) {
    int timer_id;
    memcached_return rc;
    const char *cached_ip;
    char *cached_value;
    size_t value_len;
    uint32_t flag;

    /* todo */
    timer_id = pr_timer_add(1, -1, NULL, libmemcached_deny_timeout_callback, "memcached_get");
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

    while((cached_ip = pr_str_get_token(&cached_value, "\t")) != NULL) {
        /* compare memacched IP with client IP */
        if(0 == strcmp(cached_ip, remote_ip)) {
            return true;
        }
        pr_log_debug(DEBUG2,
                     "%s: memcached IP '%s' not matched with remote IP '%s' ",
                     MODULE_NAME,  cached_ip, remote_ip);
    }

    return false;
}

static bool is_explicit_mode(void) {
    config_rec *c;
    int is_explicit;

    c = find_config(main_server->conf, CONF_PARAM, "LMDExplicitMode", FALSE);
    if(NULL == c)
        return false;

    if(NULL == c->argv[0])
        return false;

    is_explicit = *(int *) c->argv[0];
    return is_explicit ? true : false;
}

static bool is_explicit_mode_user(const char *account) {
    config_rec *c;
    pr_table_t *explicit_users;

    c = find_config(main_server->conf, CONF_PARAM, "LMDExplicitModeUser", FALSE);
    if(NULL == c)
        return false;

    if(NULL == c->argv[0])
        return false;

    explicit_users = c->argv[0];
    if(pr_table_exists(explicit_users, account) < 0 )
        return false;

    pr_log_debug(DEBUG2,
                 "%s: %s is explicit user", MODULE_NAME, account);

    return true;
}

static bool is_allowed_ip(const char *remote_ip) {
    config_rec *c;
    pr_table_t *allowed_ips;

    c = find_config(main_server->conf, CONF_PARAM, "LMDAllowFrom", FALSE);
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
    return pr_table_exists(allowed_ips, remote_ip) <= 0 ? false : true ;
}

MODRET memcached_deny_post_pass(cmd_rec *cmd) {
    /*
      development memo
      view include/netaddr.h

      pr_netaddr_get_sess_remote_name()はホスト名取って来るので微妙
      const char *remote_ip = pr_netaddr_get_sess_remote_name();

      mod_authを通過するまでは session.userは空の様子
      const char *account  = session.user;

    */
    const char *key;
    pr_netaddr_t *remote_netaddr = NULL;
    pr_netaddr_t *local_net_addr = NULL;
    const char *account   = NULL; 
    const char *remote_ip = NULL;
    const char *local_ip = NULL;

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

    if(is_explicit_mode() && !is_explicit_mode_user(account)) {
        pr_log_auth(PR_LOG_NOTICE,
                     "%s: %s is not registerd as an explicit mode user. Skip last process", MODULE_NAME, account);
        return PR_DECLINED(cmd);
    }

    remote_netaddr = pr_netaddr_get_sess_remote_addr();
    if(NULL == remote_netaddr) {
        pr_log_auth(PR_LOG_ERR, "%s: pr_netaddr_t not found. something fatal", MODULE_NAME);
        pr_response_send(R_530, _("Login denyied (server error)"));
        end_login(0);
    }

    local_net_addr = pr_netaddr_get_sess_local_addr();
    if(NULL == remote_netaddr) {
        pr_log_auth(PR_LOG_ERR, "%s: pr_netaddr_t not found. something fatal", MODULE_NAME);
        pr_response_send(R_530, _("Login denyied (server error)"));
        end_login(0);
    }

    remote_ip = pr_netaddr_get_ipstr(remote_netaddr);
    local_ip  = pr_netaddr_get_ipstr(local_net_addr);

    if(true == is_allowed_ip(remote_ip)) {
        pr_log_auth(PR_LOG_NOTICE,
                    "%s: '%s' found in Allowed IP", MODULE_NAME, remote_ip);
        return PR_DECLINED(cmd);
    }

    pr_log_debug(DEBUG2,
                "%s: '%s' not found in Allowed IP", MODULE_NAME, remote_ip);

    /* key is <account>@<proftpd IP> */
    key = pstrcat(cmd->tmp_pool, account, "@", local_ip, NULL);
    if(!key) { 
        pr_log_auth(PR_LOG_NOTICE,
                    "%s: oops, pstrcat() failed %s", MODULE_NAME, strerror(errno));
        pr_response_send(R_530, _("Login denyied (server error)"));
        end_login(0);
    }

    if(libmemcached_deny_cache_exits(memcached_deny_mmc, key, remote_ip) == false) {
        pr_log_auth(PR_LOG_NOTICE,
                    "%s: memcached IP not found for '%s', Denied", MODULE_NAME, key);
        pr_response_send(R_530, _("Login denyied"));
        end_login(0);
    }

    pr_log_debug(DEBUG2,
                 "%s: cache found. '%s' allowed to auth", MODULE_NAME, key);

    return PR_DECLINED(cmd);
}

/* ディレクティブの名前がイマイチ... */
static conftable libmemcached_deny_conftab[] = {
  { "LMDMemcachedHost",    add_libmemcached_memcached_host, NULL },
  { "LMDAllowFrom",        add_libmemcached_deny_allow_from, NULL },
  { "LMDExplicitMode",     set_libmemcached_explicit_mode, NULL },
  { "LMDExplicitModeUser", add_libmemcached_explicit_user, NULL },
  { NULL }
};
 
static cmdtable libmemcached_deny_cmdtab[] = {
  { POST_CMD, C_USER,	G_NONE,	 memcached_deny_post_pass,	FALSE,	FALSE, CL_AUTH },
  { 0, NULL }
};
 
module libmemcached_deny_module = {
  NULL, NULL,
  0x20,                    /* Module API version */
  "libmemcached_deny", /* Module name */
  libmemcached_deny_conftab,
  libmemcached_deny_cmdtab,      /* Module command handler table */
  NULL,             /* Module authentication handler table */
  libmemcached_deny_init , /* Module initialization function */
  NULL, // autoperm_sess_init  /* Session initialization function */
};
