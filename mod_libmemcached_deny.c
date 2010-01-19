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

static int libmemcached_deny_init(void) {
    memcached_deny_mmc = memcached_create(NULL);
    if(!memcached_deny_mmc) {
        pr_log_pri(PR_LOG_ERR, "Fatal %s: Out of memory", MODULE_NAME);
        exit(1);
    }
    return 0;
}

MODRET set_memcached_deny_server(cmd_rec *cmd) {
    memcached_return rc;
    memcached_server_st *server = NULL;

    /* cmd is SetAutoperm <perm> <regex_str> */
    if (cmd->argc-1 != 1)
        CONF_ERROR(cmd, "wrong number of parameters");

    /* check command context */
    CHECK_CONF(cmd, CONF_ROOT|CONF_GLOBAL);

    server = memcached_servers_parse((char *)cmd->argv[1]);
    rc = memcached_server_push(memcached_deny_mmc, server);
    if(rc != MEMCACHED_SUCCESS){
        pr_log_auth(PR_LOG_ERR,
                   "Fatal %s: failed memcached_strerror(): %s",
                    MODULE_NAME, memcached_strerror(memcached_deny_mmc, rc));
        exit(1);
    }
    pr_log_debug(DEBUG2,
                 "%s: add memcached server %s", MODULE_NAME, (char *)cmd->argv[1]);
    is_set_server = true;
    return PR_HANDLED(cmd);
}

/* todo */
static int libmemcached_deny_timeout_callback(CALLBACK_FRAME) {
    pr_log_auth(PR_LOG_WARNING,
                "%s: memcached timeout", MODULE_NAME);
    return 0;
}

static bool libmemcached_deny_cache_exits(memcached_st *mmc,
                                       const char *key,
                                       const char *local_ip) {
    int timer_id;
    memcached_return rc;
    const char *cached_ip;
    size_t value_len;
    uint32_t flag;

    /* todo */
    timer_id = pr_timer_add(1, -1, NULL, libmemcached_deny_timeout_callback, "memcached_get");
    cached_ip = memcached_get(mmc, key, strlen(key), &value_len, &flag, &rc);
    pr_timer_remove(timer_id, NULL);

    /* on failed connect to memcached */
    if(MEMCACHED_SUCCESS != rc) {
        pr_log_auth(PR_LOG_ERR,
                    "%s: failed memcached_get() %s",
                    MODULE_NAME, memcached_strerror(mmc, rc));
        return false;
    }

    /* cache not fond */
    if(NULL == cached_ip)
        return false;

    /* something wrong */
    if(0 == value_len)
        return false;

    /* compare memacched IP with local IP(proftpd's host) */
    if(0 != strcmp(cached_ip, local_ip)) {
        pr_log_auth(PR_LOG_NOTICE,
                    "%s: memcached IP '%s' not matched with local IP '%s' ",
                    MODULE_NAME,  cached_ip, local_ip);
        return false;
    }

    return true;
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
    char key[MAX_KEY_LENGTH];
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

/*      /\* Format string attack *\/ */
/*     if(NULL != strchr(account, '%')) { */
/*         pr_log_auth(PR_LOG_ERR, */
/*                     "%s: '%s' account name contains invalid character ''", */
/*                     MODULE_NAME, account); */
/*         pr_response_send(R_530, _("Login denyied")); */
/*         end_login(0); */
/*     } */

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

    if(snprintf(key, MAX_KEY_LENGTH, "%s@%s", account, remote_ip) < 0) {
        pr_log_auth(PR_LOG_NOTICE,
                    "%s: oops, snprintf() failed %s", MODULE_NAME, strerror(errno));
        pr_response_send(R_530, _("Login denyied (server error)"));
        end_login(0);
    }

    if(libmemcached_deny_cache_exits(memcached_deny_mmc, key, local_ip) == false) {
        pr_log_auth(PR_LOG_NOTICE,
                    "%s: memcached IP not found for '%s', Denied", MODULE_NAME, key);
        pr_response_send(R_530, _("Login denyied"));
        end_login(0);
    }

    pr_log_debug(DEBUG2,
                 "%s::%s(): cache found. '%s' allowd to auth", MODULE_NAME, __FUNCTION__, key);

    return PR_DECLINED(cmd);
}

static conftable libmemcached_deny_conftab[] = {
  { "LibMemcachedDenyServer",		set_memcached_deny_server,		NULL },
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
