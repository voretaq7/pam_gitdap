/* "pam_gitdap" - an LDAP authentication module for PAM
 * (C) 2020 - Michael Graziano (mikeg@bsd-box.net)
 *
 * This module is intended to be used in a git (gitea)
 * SSH server instance as a second factor authenticating
 * git users against an external LDAP directory.
 * 
 * This module is intended to be used as a second authentication
 * layer in addition to SSH keys.
 *
 * PAM Parameters
 *   ldap_uri=		The LDAP server URI
 *   dn_attr=		The DN naming attribute for users
 *   dn_base=		Where to look for the named users
 *   prompt_user	Force a username prompt
 *			(DOES NOT change pam_user value in the stack)
 *   debug		Turns on debug mode
 *
 * e.g. with ldap_uri=ldaps://127.0.0.1 , dn_attr=cn,
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

	/* General Module Variables */
	int i;
	int retval; 			// Used for internal return values
	int pam_retval = PAM_AUTH_ERR;  // What we actually return
	int style;			// PAM prompt style
	const char *pam_user;		// Used if we're not prompting.
	char *git_user = NULL;		// Used when we are prompting.
	char *git_password = NULL;	// Self Explanatory

	LDAP *ldp;			// LDAP Object Pointer
	char *bind_dn = NULL;		// LDAP Bind DN
	struct berval cred;		// LDAP Bind Password
	struct berval *servcred;	// Just a throwaway...

	int ldap_protocol=LDAP_VERSION3;
	char prompt_user = 0;
	char debug = 0;
	char *ldap_uri = NULL;	// LDAP Server URI
	char *dn_attr = NULL;	// DN naming attribute (like "cn" or "uid")
	char *dn_base = NULL;	// like "ou=users,dc=example,dc=com"

	// Initialize LDAP from Args
	for (i=0 ; i < argc ; i++) {
		if (strncmp(argv[i], "ldap_uri=", 9) == 0) {
			if (asprintf(&ldap_uri, "%s", argv[i] + 9) == -1) {
				pam_retval = PAM_BUF_ERR;
				goto PAM_GITDAP_CLEANUP;
			}
			continue;
		}
		if (strncmp(argv[i], "dn_attr=", 8) == 0) {
			if (asprintf(&dn_attr, "%s", argv[i] + 8) == -1) {
				pam_retval = PAM_BUF_ERR;
				goto PAM_GITDAP_CLEANUP;
			}
			continue;
		}
		if (strncmp(argv[i], "dn_base=", 8) == 0) {
			if (asprintf(&dn_base, "%s", argv[i] + 8) == -1) {
				pam_retval = PAM_BUF_ERR;
				goto PAM_GITDAP_CLEANUP;
			}
			continue;
		}
		if (strncmp(argv[i], "ldap_proto=", 11) == 0) {
			ldap_protocol = atoi(argv[i] + 11);
			if ( (ldap_protocol > LDAP_VERSION_MAX) ||
			     (ldap_protocol < LDAP_VERSION_MIN) ) {
				PAM_LOG("pam_gitdap Bad Protocol: Using v3.");
				ldap_protocol = LDAP_VERSION3;
			}
			continue;
		}
		if (strncmp(argv[i], "prompt_user", 11) == 0) {
			prompt_user=1;
			continue;
		}
		if (strncmp(argv[i], "debug", 5) == 0) {
			debug=1;
			continue;
		}
	}

	// Validate PAM parameters
	if ( (ldap_uri == NULL) || (dn_base == NULL) || (dn_attr == NULL) ) {
		PAM_LOG("pam_gitdap ldap_uri, dn_base, or dn_attr missing.");
		PAM_LOG("           Check PAM configuration.");
		pam_retval = PAM_SERVICE_ERR;
		goto PAM_GITDAP_CLEANUP;
	}

	// Get username
	if (prompt_user) {
		style = PAM_PROMPT_ECHO_ON;
		retval = pam_prompt(pamh, style, &git_user, "git User: ");
		if (retval != PAM_SUCCESS) {
			pam_retval = retval;
			goto PAM_GITDAP_CLEANUP;
		}
	} else {
		// Use the PAM user
		retval = pam_get_user(pamh, &pam_user, NULL);
		if (retval != PAM_SUCCESS) {
			pam_retval = retval;
			goto PAM_GITDAP_CLEANUP;
		} else {
			if (asprintf(&git_user, "%s", pam_user) == -1) {
				pam_retval = PAM_BUF_ERR;
				goto PAM_GITDAP_CLEANUP;
			}
		}
	}

	/* Get Password
	 *
	 * It doesn't make sense to use a password that has already been
	 * typed in since we haven't presented the challenge to the user
	 * yet, so clear the stored password.
	 */
	pam_set_item(pamh, PAM_AUTHTOK, NULL);
	style = PAM_PROMPT_ECHO_OFF;
	retval = pam_prompt(pamh, style, &git_password, "git Password: ");
	if (retval != PAM_SUCCESS) {
		pam_retval = PAM_BUF_ERR;
		goto PAM_GITDAP_CLEANUP;
	}
	pam_set_item(pamh, PAM_AUTHTOK, git_password);

	// Initialize LDAP credential (Password)
	cred.bv_val = git_password;
	cred.bv_len = strlen(git_password);

	// Initialize LDAP username (dn)
	if (asprintf(&bind_dn, "%s=%s,%s", dn_attr,
		      git_user, dn_base) == -1) {
		pam_retval = PAM_BUF_ERR;
		goto PAM_GITDAP_CLEANUP;
	}
	PAM_LOG("pam_gitdap BindDN: %s", bind_dn);
	PAM_LOG("pam_gitdap Server: %s", ldap_uri);

	/*
	 * Actually connect to the LDAP server and try to bind.
	*/
	if (ldap_initialize(&ldp, ldap_uri) == LDAP_SUCCESS) {
		if ( ldap_set_option(ldp, LDAP_OPT_PROTOCOL_VERSION,
		      &ldap_protocol) == LDAP_SUCCESS ) {
			retval = ldap_sasl_bind_s(ldp, bind_dn,
			         LDAP_SASL_SIMPLE, &cred,
			         NULL, NULL, &servcred);
			PAM_LOG("LDAP Bind: %s", ldap_err2string(retval));
			if (retval == LDAP_SUCCESS) {
				pam_retval = PAM_SUCCESS;
				ldap_unbind_ext_s(ldp, NULL, NULL);
			} else {
				pam_retval = PAM_AUTH_ERR;
			}
		} else {
			PAM_LOG("LDAP Couldn't set LDAP protocol %d",
				 ldap_protocol);
			pam_retval = PAM_SERVICE_ERR;
		}
	} else {
		PAM_LOG("pam_gitdap Initialize failed: %s",
			ldap_err2string(retval));
		pam_retval = PAM_SERVICE_ERR;
	}


	// Clean up everything we threw on the heap
	PAM_GITDAP_CLEANUP:	// Shut up I know GOTOs are bad.
	free(git_user);
	free(git_password);
	free(bind_dn);
	free(ldap_uri);
	free(dn_attr);
	free(dn_base);

	// Return the PAM status
	return (pam_retval);
}

PAM_MODULE_ENTRY("pam_gitdap");
