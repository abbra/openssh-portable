/*
This simple pam module saves the content of SSH_USER_AUTH variable to /tmp/SSH_USER_AUTH
file.

Setup:
  - gcc -fPIC -DPIC -shared -rdynamic -o pam_save_ssh_var.o pam_save_ssh_var.c
  - copy pam_save_ssh_var.o to /lib/security resp. /lib64/security
  - add to /etc/pam.d/sshd
	auth	requisite	pam_save_ssh_var.o
*/

/* Define which PAM interfaces we provide */
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <stdio.h>

int save_ssh_var(pam_handle_t *pamh, const char *phase) {
	FILE *fp;
	const char *var;

	fp = fopen("/tmp/SSH_USER_AUTH","a");
	fprintf(fp, "BEGIN (%s)\n", phase);
	var = pam_getenv(pamh, "SSH_USER_AUTH");
	if (var != NULL) {
		fprintf(fp, "SSH_USER_AUTH: '%s'\n", var);
	}
	fprintf(fp, "END (%s)\n", phase);
	fclose(fp);

	return 0;
}

/* PAM entry point for session creation */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

/* PAM entry point for accounting */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	save_ssh_var(pamh, "auth");
	return(PAM_IGNORE);
}

/*
   PAM entry point for setting user credentials (that is, to actually
   establish the authenticated user's credentials to the service provider)
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return(PAM_IGNORE);
}

