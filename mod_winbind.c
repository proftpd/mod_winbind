/*
 * mod_winbind - ProFTPD authentication to Windows domains via Samba winbindd
 * Copyright (c) 2012, John Morrissey <jwm@horde.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 */

/* $Libraries: -lwbclient$ */

#include "conf.h"
#include "privs.h"

#include <stdbool.h>
#include <wbclient.h>

#define MOD_WINBIND_VERSION	"mod_winbind/1.0"

static int enable_winbind = 0;

/* FIXME: make sure we aren't returning libwbclient-allocated structs
 * in proftpd module handlers.
 */

MODRET
handle_winbind_getpwnam(cmd_rec *cmd)
{
  struct passwd *pw, *ret_pw;
  wbcErr ret;

  if (!enable_winbind) {
    return PR_DECLINED(cmd);
  }

  ret = wbcGetpwnam(cmd->argv[0], &pw);
  if (!WBC_ERROR_IS_OK(ret)) {
    printf("getpwnam(): %d\n", ret);
    return PR_DECLINED(cmd);
  }

  ret_pw = palloc(session.pool, sizeof(struct passwd));
  if (ret_pw == NULL) {
    return PR_DECLINED(cmd);
  }

  memcpy(ret_pw, pw, sizeof(struct passwd));
  return mod_create_data(cmd, ret_pw);
}

MODRET
handle_winbind_getpwuid(cmd_rec *cmd)
{
  struct passwd *pw, *ret_pw;
  wbcErr ret;

  if (!enable_winbind) {
    return PR_DECLINED(cmd);
  }

  ret = wbcGetpwuid(*((uid_t *) cmd->argv[0]), &pw);
  if (!WBC_ERROR_IS_OK(ret)) {
    printf("getpwnam(): %d\n", ret);
    return PR_DECLINED(cmd);
  }

  ret_pw = palloc(session.pool, sizeof(struct passwd));
  if (ret_pw == NULL) {
    return PR_DECLINED(cmd);
  }

  memcpy(ret_pw, pw, sizeof(struct passwd));
  return mod_create_data(cmd, ret_pw);
}

MODRET
handle_winbind_getgrnam(cmd_rec *cmd)
{
  struct group *gr, *ret_gr;
  wbcErr ret;

  if (!enable_winbind) {
    return PR_DECLINED(cmd);
  }

  ret = wbcGetgrnam(cmd->argv[0], &gr);
  if (!WBC_ERROR_IS_OK(ret)) {
    printf("getpwnam(): %d\n", ret);
    return PR_DECLINED(cmd);
  }

  ret_gr = palloc(session.pool, sizeof(struct group));
  if (ret_gr == NULL) {
    return PR_DECLINED(cmd);
  }

  memcpy(ret_gr, gr, sizeof(struct group));
  return mod_create_data(cmd, ret_gr);
}

MODRET
handle_winbind_getgrgid(cmd_rec *cmd)
{
  struct group *gr, *ret_gr;
  wbcErr ret;

  if (!enable_winbind) {
    return PR_DECLINED(cmd);
  }

  ret = wbcGetgrgid(*((gid_t *) cmd->argv[0]), &gr);
  if (!WBC_ERROR_IS_OK(ret)) {
    printf("getpwnam(): %d\n", ret);
    return PR_DECLINED(cmd);
  }

  ret_gr = palloc(session.pool, sizeof(struct group));
  if (ret_gr == NULL) {
    return PR_DECLINED(cmd);
  }

  memcpy(ret_gr, gr, sizeof(struct group));
  return mod_create_data(cmd, ret_gr);
}

MODRET
handle_winbind_getgroups(cmd_rec *cmd)
{
  unsigned int i;
  uint32_t num_groups;
  gid_t *winbind_groups;
  struct passwd *pw;
  struct group *gr;
  array_header *gids   = (array_header *) cmd->argv[1],
               *groups = (array_header *) cmd->argv[2];
  wbcErr ret;

  if (!enable_winbind) {
    return PR_DECLINED(cmd);
  }

  if (!gids || !groups) {
    return PR_DECLINED(cmd);
  }

  ret = wbcGetpwnam(cmd->argv[0], &pw);
  if (!WBC_ERROR_IS_OK(ret)) {
    if (ret == WBC_ERR_UNKNOWN_USER) {
      return PR_DECLINED(cmd);
    }
    /* FIXME: what to do on transient errors? */
    /* FIXME: what about the case where users come from one auth
     * module, and groups come from us?
     */
    printf("getpwnam(): %d\n", ret);
    return PR_DECLINED(cmd);
  }

  ret = wbcGetgrgid(pw->pw_gid, &gr);
  if (!WBC_ERROR_IS_OK(ret)) {
    pr_log_debug(DEBUG3, MOD_WINBIND_VERSION ": couldn't determine group name for user %s primary group %lu, skipping.", pw->pw_name, (unsigned long)pw->pw_gid);
    return PR_DECLINED(cmd);
  }

  pr_log_debug(DEBUG3, MOD_WINBIND_VERSION ": adding user %s primary group %s/%lu", pw->pw_name, gr->gr_name, (unsigned long)pw->pw_gid);
  *((gid_t *) push_array(gids)) = pw->pw_gid;
  *((char **) push_array(groups)) = pstrdup(session.pool, gr->gr_name);

  ret = wbcGetGroups(cmd->argv[0], &num_groups, &winbind_groups);
  if (!WBC_ERROR_IS_OK(ret)) {
    printf("getgroups(): %d\n", ret);
    return PR_DECLINED(cmd);
  }

  pr_log_debug(DEBUG3, MOD_WINBIND_VERSION ": user %s has %u secondary groups",
    pw->pw_name, num_groups);
  for (i = 0; i < num_groups; ++i) {
    ret = wbcGetgrgid(winbind_groups[i], &gr);
    if (!WBC_ERROR_IS_OK(ret)) {
      printf("getgrgid(%d): %d\n", winbind_groups[num_groups], ret);
      return PR_DECLINED(cmd);
    }

    *((gid_t *) push_array(gids)) = winbind_groups[i];
    *((char **) push_array(groups)) =
      pstrdup(session.pool, gr->gr_name);
    pr_log_debug(DEBUG3,
      MOD_WINBIND_VERSION ": added user %s secondary group %s/%u",
      pw->pw_name, gr->gr_name, gr->gr_gid);
  }

  if (gids->nelts <= 0) {
    /* Let other modules have a shot. */
    return PR_DECLINED(cmd);
  }
  return mod_create_data(cmd, (void *) &gids->nelts);
}

/* cmd->argv[0] : user name
 * cmd->argv[1] : cleartext password
 */
MODRET
handle_winbind_is_auth(cmd_rec *cmd)
{
  const char *username = cmd->argv[0];
  struct passwd *pw;
  wbcErr ret;

  if (!enable_winbind) {
    return PR_DECLINED(cmd);
  }

  ret = wbcGetpwnam(cmd->argv[0], &pw);
  if (!WBC_ERROR_IS_OK(ret)) {
    if (ret == WBC_ERR_UNKNOWN_USER) {
      /* Let other modules have a shot. */
      return PR_DECLINED(cmd);
    }
    /* FIXME: what to do on transient errors? */
    printf("getpwnam(): %d\n", ret);
    return PR_DECLINED(cmd);
  }

  if (pr_auth_check(cmd->tmp_pool, NULL, username, cmd->argv[1])) {
    pr_log_debug(DEBUG3, MOD_WINBIND_VERSION ": bad password for %s", pw->pw_name);
    return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
  }

  session.auth_mech = "mod_winbind.c";
  return PR_HANDLED(cmd);
}

/* cmd->argv[0] = hashed password,
 * cmd->argv[1] = user,
 * cmd->argv[2] = cleartext
 */
MODRET
handle_winbind_check(cmd_rec *cmd)
{
  wbcErr ret;

  if (!enable_winbind) {
    return PR_DECLINED(cmd);
  }

  ret = wbcAuthenticateUser(cmd->argv[1], cmd->argv[2]);
  if (!WBC_ERROR_IS_OK(ret)) {
    if (ret != WBC_ERR_AUTH_ERROR) {
      pr_log_pri(PR_LOG_ERR,
        MOD_WINBIND_VERSION ": authentication call failed for user %s: %s",
        cmd->argv[1], wbcErrorString(ret));
    }
    pr_log_debug(DEBUG3, MOD_WINBIND_VERSION ": invalid credentials for %s",
      cmd->argv[1]);
    return PR_ERROR(cmd);
  }
  session.auth_mech = "mod_winbind.c";
  return PR_HANDLED(cmd);
}

MODRET
handle_winbind_uid_name(cmd_rec *cmd)
{
  struct passwd *pw;
  wbcErr ret;

  if (!enable_winbind) {
    return PR_DECLINED(cmd);
  }

  ret = wbcGetpwuid(*((uid_t *) cmd->argv[0]), &pw);
  if (!WBC_ERROR_IS_OK(ret)) {
    printf("getpwnam(): %d\n", ret);
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, pstrdup(permanent_pool, pw->pw_name));
}

MODRET
handle_winbind_gid_name(cmd_rec *cmd)
{
  struct group *gr;
  wbcErr ret;

  if (!enable_winbind) {
    return PR_DECLINED(cmd);
  }

  ret = wbcGetgrgid(*((gid_t *) cmd->argv[0]), &gr);
  if (!WBC_ERROR_IS_OK(ret)) {
    printf("getpwnam(): %d\n", ret);
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, pstrdup(permanent_pool, gr->gr_name));
}

MODRET
handle_winbind_name_uid(cmd_rec *cmd)
{
  struct passwd *pw;
  wbcErr ret;

  if (!enable_winbind) {
    return PR_DECLINED(cmd);
  }

  ret = wbcGetpwnam(cmd->argv[0], &pw);
  if (!WBC_ERROR_IS_OK(ret)) {
    printf("getpwnam(): %d\n", ret);
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, (void *) &pw->pw_uid);
}

MODRET
handle_winbind_name_gid(cmd_rec *cmd)
{
  struct group *gr;
  wbcErr ret;

  if (!enable_winbind) {
    return PR_DECLINED(cmd);
  }

  ret = wbcGetgrnam(cmd->argv[0], &gr);
  if (!WBC_ERROR_IS_OK(ret)) {
    printf("getpwnam(): %d\n", ret);
    return PR_DECLINED(cmd);
  }

  return mod_create_data(cmd, (void *) &gr->gr_gid);
}

MODRET
set_enable_winbind(cmd_rec *cmd)
{
  int b;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT | CONF_VIRTUAL | CONF_GLOBAL);

  b = get_boolean(cmd, 1);
  if (b == -1) {
    CONF_ERROR(cmd, "EnableWinbind: expected a boolean value for first argument.");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;
  return PR_HANDLED(cmd);
}

static int
winbind_getconf(void)
{
  void *ptr;

  ptr = get_param_ptr(main_server->conf, "EnableWinbind", FALSE);
  if (ptr) {
    enable_winbind = *((int *) ptr);
  }

  return 0;
}

static int winbind_mod_init(void) {
  pr_log_debug(DEBUG2, MOD_WINBIND_VERSION ": compiled using %s %d.%d",
    WBCLIENT_VENDOR_VERSION, WBCLIENT_MAJOR_VERSION,
    WBCLIENT_MINOR_VERSION);

  return 0;
}

static conftable winbind_config[] = {
  { "EnableWinbind", set_enable_winbind, NULL },
  { NULL, NULL, NULL },
};

static authtable winbind_auth[] = {
  { 0, "getpwnam", handle_winbind_getpwnam },
  { 0, "getpwuid", handle_winbind_getpwuid },
  { 0, "getgrnam", handle_winbind_getgrnam },
  { 0, "getgrgid", handle_winbind_getgrgid },
  { 0, "getgroups", handle_winbind_getgroups },
  { 0, "auth", handle_winbind_is_auth },
  { 0, "check", handle_winbind_check },
  { 0, "uid2name", handle_winbind_uid_name },
  { 0, "gid2name", handle_winbind_gid_name },
  { 0, "name2uid", handle_winbind_name_uid },
  { 0, "name2gid", handle_winbind_name_gid },
  { 0, NULL }
};

module winbind_module = {
  NULL, NULL, /* Always NULL */
  0x20, /* API Version 2.0 */
  "winbind",
  winbind_config, /* Configuration directive table */
  NULL, /* Command handlers */
  winbind_auth, /* Authentication handlers */
  winbind_mod_init, /* Initialization functions */
  winbind_getconf,
  MOD_WINBIND_VERSION
};
