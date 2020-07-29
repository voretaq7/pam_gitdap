/* "pam_gitdap" - an LDAP authentication module for PAM
 * (C) 2020 - Michael Graziano (mikeg@bsd-box.net)
 *
 * This module is intended to be used in a git (gitea)
 * SSH server instance as a second factor authenticating
 * git users against an external LDAP directory.
 * 
 * It prompts for both the git username and git password.
 *
 * It assumes that every git user will have SSH keys
 * configured in .ssh/authorized_keys and that every
 * git user also exists in the LDAP directory.
 *
 * PAM Parameters
 *   ldap_server	The LDAP server URI
 *   dn_attr		The DN naming attribute for users
 *   dn_base		Where to look for the named users
 *
 * e.g. with ldap_server=ldaps://127.0.0.1 , dn_attr=cn,
 *           dn_base=ou=users,dc=example,dc=com
 * the module will attempt to bind to LDAP Server at 127.0.0.1 (with SSL)
 * as cn=<Username>,ou=users,dc=example,dc=com with the password provided.
 *
 * If the bind succeeds the user is authorized ; if it fails the user
 * is NOT authorized.
 *
*/
#include <sys/cdefs.h>

#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAM_SM_AUTH

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>

#include <ldap.h>

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags __unused,
    int argc, const char *argv[])
{
	int i;
	int retval; // Used for a bunch of internal return values
	int pam_retval = PAM_AUTH_ERR; // What we actually return
	int style;
	LDAP *ldp;
	char *bind_dn;
	struct berval cred;
	struct berval *servcred;

	char *git_user = NULL;
	char *git_password = NULL;

	char *ldap_server = NULL;
	char *dn_attr = NULL;
	char *dn_base = NULL;

	// Initialize LDAP from Args
	for (i=0 ; i < argc ; i++) {
		PAM_LOG("arg %d: %s", i, argv[i]);
		if (strncmp(argv[i], "ldap_server=", 12) == 0) {
			retval = asprintf(&ldap_server, "%s", argv[i] + 12);
			if (retval == -1) {
				return (PAM_BUF_ERR);
			}
		}
		if (strncmp(argv[i], "dn_attr=", 8) == 0) {
			retval = asprintf(&dn_attr, "%s", argv[i] + 8);
			if (retval == -1) {
				return (PAM_BUF_ERR);
			}
		}
		if (strncmp(argv[i], "dn_base=", 8) == 0) {
			retval = asprintf(&dn_base, "%s", argv[i] + 8);
			if (retval == -1) {
				return (PAM_BUF_ERR);
			}
		}
	}

	style = PAM_PROMPT_ECHO_ON;
	retval = pam_prompt(pamh, style, &git_user, "git user: ");
	if (retval != PAM_SUCCESS) {
		return (retval);
	}
	PAM_LOG("Got user: %s", git_user);

	/*
	 * It doesn't make sense to use a password that has already been
	 * typed in, since we haven't presented the challenge to the user
	 * yet, so clear the stored password.
	 */
	pam_set_item(pamh, PAM_AUTHTOK, NULL);

	style = PAM_PROMPT_ECHO_OFF;
	retval = pam_prompt(pamh, style, &git_password, "git Password: ");
	if (retval != PAM_SUCCESS) {
		return (retval);
	}
	PAM_LOG("Got password: %s", git_password);
	pam_set_item(pamh, PAM_AUTHTOK, git_password);

	// Initialize credential (Password)
	cred.bv_val = git_password;
	cred.bv_len = strlen(git_password);
	PAM_LOG("Set BER credential");

	// Initialize username (dn)
	asprintf(&bind_dn, "%s=%s,%s",
		 dn_attr, git_user, dn_base);
	if (retval == -1) {
		return (PAM_BUF_ERR);
	}
	PAM_LOG("BindDN: %s", bind_dn);
	PAM_LOG("Server: %s", ldap_server);

	/*
	 * Actually connect to the LDAP server and try to bind.
	*/
	retval = ldap_initialize(&ldp, ldap_server);
	PAM_LOG("LDAP Init: %s", ldap_err2string(retval));

	retval = ldap_sasl_bind_s(ldp, bind_dn, LDAP_SASL_SIMPLE,
	         &cred, NULL, NULL, &servcred);
	PAM_LOG("LDAP Bind: %s", ldap_err2string(retval));
	if (retval == LDAP_SUCCESS) {
		pam_retval = PAM_SUCCESS;
	} else {
		pam_retval = PAM_AUTH_ERR;
	}

	retval = ldap_unbind_ext_s(ldp, NULL, NULL);
	PAM_LOG("LDAP Unbind: %s", ldap_err2string(retval));

	// Clean up everything we threw on the heap
	free(git_user);
	free(git_password);
	free(bind_dn);
	free(ldap_server);
	free(dn_attr);
	free(dn_base);

	return (pam_retval);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{

	return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_gitdap");
