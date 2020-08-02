pam_gitdap(8) -- PAM module for authenticating git users against LDAP
=====================================================================

## SYNOPSIS
_[service-name]_ auth _control-flag_ pam_gitdap _[module configuration]_

## DESCRIPTION
`pam_gitdap` provides PAM authentication through a simple LDAP bind.
It is designed to allow a user's LDAP username/password to be used as a
second authentication factor for git hosting services such as Gitea or Gogs.

## MODULE CONFIGURATION
The following values are mandatory in the PAM module configuration:

* `ldap_uri=`_URI_:
  The LDAP URI address for the LDAP server to bind to.
  Format is _ldap://host:port_ or _ldaps://host:port_

* `dn_attr=`_Attribute_:
  The Bind DN naming attribute, for example _cn_ or _uid_.

* `dn_base=`_Base_:
  The base of the Bind DN, appended after the naming attribute.  
  For example _ou=users,dc=example,dc=com_.

The following values are optional in the PAM configuration:

* `prompt_user`:
  Prompt for the git username. This is used if multiple git users
  share a single ssh account, which is typically the case for
  services like Gitea.  

* `debug`:
  Enables module debugging.

## USAGE RECOMMENDATIONS
It is recommended to create a second SSH server exclusively for git,
running on an alternate port. You may do this by creating a symbolic 
link from your system `sshd` binary to an alternate name such as
`/usr/local/sbin/git-sshd`.

Create a separate PAM configuration for the `git-sshd` service which
includes an `auth` entry for this module along with any other PAM
modules you wish to use.

The _sshd_config_ file for this server must have the
`ChallengeResponseAuthentication` option set to `yes` to allow the PAM
module to prompt for the LDAP password and/or username.  
It should also have `AllowUsers` set to only your git service user and
`AuthenticationMethods` set to `publickey,keyboard-interactive`. This
will require your users to prevent a valid SSH key before being prompted
for their LDAP credentials.

**IT IS NOT RECOMMENDED TO USE THIS MODULE AS YOUR ONLY AUTHENTICATION
METHOD. IT SHOULD ALWAYS BE USED IN CONJUNCTION WITH SSH KEYS AS
DESCRIBED ABOVE, OR AS PART OF A MORE COMPREHENSIVE PAM STACK.**  

## MODULE OPERATION
The module will attempt to bind to the LDAP directory as  
"`dn_attr`=_username_,`dn_base`" using the password supplied by the user. 

It returns one of the following PAM result codes:

* `PAM_SUCCESS`: 
  The LDAP bind succeeded.

* `PAM_AUTH_ERR`:
  The LDAP bind failed.

* `PAM_SERVICE_ERR`:
  The module configuration is invalid (one or more mandatory values missing).

* `PAM_BUF_ERR`:
  An internal error occurred in string processing/manipulation.

## BUGS
**Only a simple bind is performed**  
This is insecure unless used over TLS (ldaps://) connections.

**No validation is performed on user-supplied usernames**
This is intentional as it allows for flexibility in the username.  
For example if configured with `dn_attr= dn_base= prompt_user` the
username expected would be the full LDAP DN to bind as.

**No validation is performed on dn_attr or dn_base**  
This is intentional as it allows more complex Bind DNs to be constructed.

## COPYRIGHT
pam_gitdap is copyright (C) 2020 Michael Graziano.  
Source is available at _https://github.com/voretaq7/pam_gitdap_

## SEE ALSO
pam(8), pam.conf(5)

