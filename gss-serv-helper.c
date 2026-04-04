/*
 * Copyright (c) 2026 Alexander Bokovoy <abokovoy@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * sshd-session side of the sshd-gssapi-helper protocol.
 *
 * Provides:
 *   ssh_gssapi_helper_start()     — fork/exec the helper, store fd
 *   ssh_gssapi_helper_stop()      — close fd, reap helper
 *   ssh_gssapi_helper_impersonate()        — vtable: S4U2Self + storecreds
 *   ssh_gssapi_helper_storecreds_impersonated() — vtable: no-op (done in helper)
 *   ssh_gssapi_helper_delegate()           — vtable: S4U2Proxy
 *   ssh_gssapi_helper_filter_creds()       — vtable: ccache filter
 *   ssh_gssapi_helper_cleanup()            — vtable: destroy ccache, stop helper
 *
 * The helper is spawned once per authenticated session (after auth, before
 * the shell/command is exec'd).  It starts as root so it can read the host
 * keytab, then permanently drops to the target user UID after storing the
 * impersonated credential.
 */

#include "includes.h"

#if defined(GSSAPI) && defined(KRB5) && !defined(HEIMDAL) && defined(WITH_OPENSSL)

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "log.h"
#include "misc.h"
#include "atomicio.h"
#include "pathnames.h"
#include "packet.h"
#include "ssh2.h"
#include "kex.h"
#include "hostfile.h"
#include "auth.h"
#include "channels.h"
#include "session.h"
#include "ssherr.h"

#include "ssh-gss.h"
#include "sshd-gssapi-helper.h"

/* One helper per session */
static struct {
	pid_t	pid;
	int	fd;
} helper = { -1, -1 };

/* ------------------------------------------------------------------ *
 * Low-level framing — identical to ssh-pkcs11-client.c
 * ------------------------------------------------------------------ */

static void
helper_send(struct sshbuf *msg)
{
	u_char	 lbuf[4];
	size_t	 mlen = sshbuf_len(msg);

	POKE_U32(lbuf, mlen);
	if (atomicio(vwrite, helper.fd, lbuf, 4) != 4 ||
	    atomicio(vwrite, helper.fd,
	        sshbuf_mutable_ptr(msg), mlen) != mlen)
		error_f("write to sshd-gssapi-helper failed: %s",
		    strerror(errno));
}

/*
 * Receive one message with a timeout.
 * Returns the message-type byte, or 0 on error/timeout.
 */
static int
helper_recv(struct sshbuf *msg)
{
	struct pollfd	pfd;
	u_char		lbuf[4], type, buf[4096];
	u_int		msglen, chunk;
	int		r;

	pfd.fd     = helper.fd;
	pfd.events = POLLIN;

	r = poll(&pfd, 1, SSH_GSSAPI_HLP_TIMEOUT_SEC * 1000);
	if (r == 0) {
		error_f("sshd-gssapi-helper: timeout after %d seconds",
		    SSH_GSSAPI_HLP_TIMEOUT_SEC);
		return 0;
	}
	if (r < 0) {
		error_f("poll: %s", strerror(errno));
		return 0;
	}

	sshbuf_reset(msg);
	if (atomicio(read, helper.fd, lbuf, 4) != 4) {
		error_f("short read from sshd-gssapi-helper");
		return 0;
	}
	msglen = PEEK_U32(lbuf);
	if (msglen > SSH_GSSAPI_HLP_MAX_MSG) {
		error_f("sshd-gssapi-helper: response too large (%u)", msglen);
		return 0;
	}
	while (msglen > 0) {
		chunk = msglen < sizeof(buf) ? msglen : (u_int)sizeof(buf);
		if (atomicio(read, helper.fd, buf, chunk) != chunk) {
			error_f("read from sshd-gssapi-helper failed");
			return 0;
		}
		if ((r = sshbuf_put(msg, buf, chunk)) != 0)
			fatal_fr(r, "sshbuf_put");
		msglen -= chunk;
	}
	if ((r = sshbuf_get_u8(msg, &type)) != 0)
		fatal_fr(r, "parse response type");
	return (int)type;
}

/* ------------------------------------------------------------------ *
 * Lifecycle
 * ------------------------------------------------------------------ */

/*
 * Fork and exec sshd-gssapi-helper.  Must be called as root before the
 * session process drops privileges.  The socketpair is inherited across
 * the privsep fork; both the monitor and the session child receive the fd.
 *
 * Returns 0 on success, -1 on failure.
 */
int
ssh_gssapi_helper_start(void)
{
	int	pair[2];
	pid_t	pid;
	char   *prog, *verbosity = NULL;

	if (helper.fd != -1)
		return 0; /* already running */

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error_f("socketpair: %s", strerror(errno));
		return -1;
	}

	if ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		return -1;
	}

	if (pid == 0) {
		/* child → becomes the helper */
		if (dup2(pair[1], STDIN_FILENO)  == -1 ||
		    dup2(pair[1], STDOUT_FILENO) == -1) {
			fprintf(stderr, "dup2: %s\n", strerror(errno));
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		prog = getenv("SSHD_GSSAPI_HELPER");
		if (prog == NULL || prog[0] == '\0')
			prog = _PATH_SSHD_GSSAPI_HELPER;
		if (log_level_get() >= SYSLOG_LEVEL_DEBUG1)
			verbosity = "-vvv";
		execlp(prog, prog, verbosity, (char *)NULL);
		/* exec failed — write to stderr as a last resort */
		fprintf(stderr, "exec %s: %s\n", prog, strerror(errno));
		_exit(1);
	}

	/* parent */
	close(pair[1]);
	helper.pid = pid;
	helper.fd  = pair[0];
	debug_f("sshd-gssapi-helper started (%s), pid %ld fd %d",
	    getenv("SSHD_GSSAPI_HELPER") ? getenv("SSHD_GSSAPI_HELPER")
	        : _PATH_SSHD_GSSAPI_HELPER,
	    (long)pid, pair[0]);
	return 0;
}

void
ssh_gssapi_helper_stop(void)
{
	int status;

	if (helper.fd != -1) {
		close(helper.fd);
		helper.fd = -1;
	}
	if (helper.pid != -1) {
		waitpid(helper.pid, &status, 0);
		if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			debug_f("sshd-gssapi-helper exited with status %d",
			    WEXITSTATUS(status));
		helper.pid = -1;
	}
}

/* ------------------------------------------------------------------ *
 * Key serialisation helpers
 * ------------------------------------------------------------------ */

/*
 * Append an SSH public-key blob to msg.  If key is NULL, appends a
 * zero-length string so the helper knows no key was available.
 */
static int
put_pubkey_blob(struct sshbuf *msg, const struct sshkey *key)
{
	u_char *blob = NULL;
	size_t  bloblen = 0;
	int     r;

	if (key != NULL) {
		if ((r = sshkey_to_blob(key, &blob, &bloblen)) != 0) {
			error_fr(r, "sshkey_to_blob");
			return r;
		}
	}
	r = sshbuf_put_string(msg, blob, bloblen);
	free(blob);
	return r;
}

/* ------------------------------------------------------------------ *
 * vtable: impersonate
 *
 * Serialises session context into an IMPERSONATE request, sends it to
 * the helper, and parses the SUCCESS response into client->store so
 * that ssh_gssapi_do_child() and ssh_gssapi_cleanup_creds() work.
 *
 * Runs as ROOT (before privilege drop).
 * ------------------------------------------------------------------ */
int
ssh_gssapi_helper_impersonate(ssh_gssapi_client *client,
    const char *user, u_int lifetime,
    struct ssh *ssh, struct Authctxt *authctxt)
{
	struct sshbuf  *msg = NULL;
	char		lname[NI_MAXHOST];
	char	       *client_addr = NULL;
	const char     *auth_method = "unknown";
	const char     *key_fp = "";
	char	       *method_buf = NULL;
	const struct sshkey *host_pubkey = NULL;
	int		type, r, ret = -1;
	char	       *ccache_envval = NULL, *ccache_filename = NULL;
	u_char		set_env;
	u_int		target_uid, target_gid;

	if (helper.fd == -1) {
		error_f("helper not running");
		return -1;
	}
	if (authctxt == NULL || authctxt->pw == NULL) {
		error_f("no authctxt");
		return -1;
	}

	target_uid = (u_int)authctxt->pw->pw_uid;
	target_gid = (u_int)authctxt->pw->pw_gid;

	if (gethostname(lname, sizeof(lname)) != 0) {
		error_f("gethostname: %s", strerror(errno));
		return -1;
	}

	/* Extract auth method string from session_info */
	if (authctxt->session_info != NULL &&
	    sshbuf_len(authctxt->session_info) > 0) {
		const char *si = (const char *)sshbuf_ptr(
		    authctxt->session_info);
		size_t si_len  = sshbuf_len(authctxt->session_info);
		const char *sp = memchr(si, ' ',  si_len);
		const char *nl = memchr(si, '\n', si_len);
		size_t mlen    = sp ? (size_t)(sp - si)
		    : nl ? (size_t)(nl - si) : si_len;
		method_buf  = xmalloc(mlen + 1);
		memcpy(method_buf, si, mlen);
		method_buf[mlen] = '\0';
		auth_method = method_buf;
	}

	/* Client key fingerprint (auth_method_info already a string) */
	if (authctxt->auth_method_info != NULL)
		key_fp = authctxt->auth_method_info;

	/* Client address "ip:port" */
	if (ssh != NULL) {
		const char *ip   = ssh_remote_ipaddr(ssh);
		int         port = ssh_remote_port(ssh);
		if (ip != NULL)
			xasprintf(&client_addr, "%s:%d", ip, port);
	}

	/* Prefer RSA → ECDSA → Ed25519 host public key */
	if (ssh != NULL) {
		host_pubkey = get_hostkey_public_by_type(KEY_RSA, 0, ssh);
		if (host_pubkey == NULL)
			host_pubkey = get_hostkey_public_by_type(
			    KEY_ECDSA, 0, ssh);
		if (host_pubkey == NULL)
			host_pubkey = get_hostkey_public_by_type(
			    KEY_ED25519, 0, ssh);
	}

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	if ((r = sshbuf_put_u8(msg, SSH_GSSAPI_HLP_IMPERSONATE))          != 0 ||
	    (r = sshbuf_put_cstring(msg, user))                            != 0 ||
	    (r = sshbuf_put_cstring(msg, lname))                           != 0 ||
	    (r = sshbuf_put_cstring(msg, auth_method))                     != 0 ||
	    (r = sshbuf_put_cstring(msg, client_addr ? client_addr : "")) != 0 ||
	    (r = sshbuf_put_cstring(msg, key_fp))                          != 0)
		fatal_fr(r, "compose header");

	/* session_id blob */
	if (ssh != NULL && ssh->kex != NULL &&
	    ssh->kex->session_id != NULL) {
		if ((r = sshbuf_put_stringb(msg, ssh->kex->session_id)) != 0)
			fatal_fr(r, "compose session_id");
	} else {
		if ((r = sshbuf_put_string(msg, NULL, 0)) != 0)
			fatal_fr(r, "compose empty session_id");
	}

	/* host and client public keys as SSH blobs */
	if ((r = put_pubkey_blob(msg, host_pubkey))                        != 0 ||
	    (r = put_pubkey_blob(msg, authctxt->auth_method_key))          != 0)
		fatal_fr(r, "compose pubkeys");

	if ((r = sshbuf_put_u32(msg, lifetime))                            != 0 ||
	    (r = sshbuf_put_u32(msg, target_uid))                          != 0 ||
	    (r = sshbuf_put_u32(msg, target_gid))                          != 0)
		fatal_fr(r, "compose tail");

	helper_send(msg);
	sshbuf_reset(msg);

	type = helper_recv(msg);
	if (type != SSH_GSSAPI_HLP_SUCCESS) {
		error_f("IMPERSONATE failed (type %d)", type);
		goto out;
	}

	if ((r = sshbuf_get_cstring(msg, &ccache_envval, NULL))   != 0 ||
	    (r = sshbuf_get_cstring(msg, &ccache_filename, NULL)) != 0 ||
	    (r = sshbuf_get_u8(msg, &set_env))                    != 0)
		fatal_fr(r, "parse IMPERSONATE reply");

	/* Populate gssapi_client.store */
	client->store.envval   = ccache_envval;   ccache_envval = NULL;
	if (ccache_filename != NULL && ccache_filename[0] != '\0') {
		client->store.filename = ccache_filename;
		ccache_filename = NULL;
	} else {
		free(ccache_filename);
		ccache_filename = NULL;
	}
	if (set_env)
		client->store.envvar = xstrdup("KRB5CCNAME");

	debug_f("impersonation succeeded; ccache=%s", client->store.envval);
	ret = 0;

out:
	sshbuf_free(msg);
	free(method_buf);
	free(client_addr);
	free(ccache_envval);
	free(ccache_filename);
	return ret;
}

/*
 * vtable: storecreds_impersonated — no-op.
 *
 * The helper already copied the evidence ticket into the user ccache as
 * the final step of IMPERSONATE before replying SUCCESS.
 */
void
ssh_gssapi_helper_storecreds_impersonated(ssh_gssapi_client *client)
{
	(void)client;
	debug_f("no-op: helper stored impersonated creds during IMPERSONATE");
}

/* ------------------------------------------------------------------ *
 * vtable: delegate — S4U2Proxy for each service principal.
 * Runs as target_uid (helper already dropped privs).
 * ------------------------------------------------------------------ */
void
ssh_gssapi_helper_delegate(ssh_gssapi_client *client,
    const char **services, u_int nservices, u_int lifetime)
{
	struct sshbuf *msg;
	u_int	       i;
	int	       r;

	(void)client;

	if (helper.fd == -1 || nservices == 0)
		return;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	if ((r = sshbuf_put_u8(msg,  SSH_GSSAPI_HLP_DELEGATE)) != 0 ||
	    (r = sshbuf_put_u32(msg, nservices))                != 0)
		fatal_fr(r, "compose DELEGATE header");
	for (i = 0; i < nservices; i++) {
		if ((r = sshbuf_put_cstring(msg, services[i])) != 0)
			fatal_fr(r, "compose service");
	}
	if ((r = sshbuf_put_u32(msg, lifetime)) != 0)
		fatal_fr(r, "compose lifetime");

	helper_send(msg);
	sshbuf_reset(msg);

	if (helper_recv(msg) != SSH_GSSAPI_HLP_SUCCESS)
		error_f("DELEGATE failed");

	sshbuf_free(msg);
}

/* ------------------------------------------------------------------ *
 * vtable: filter_creds — remove unwanted ticket classes from ccache.
 * Runs as target_uid.
 * ------------------------------------------------------------------ */
void
ssh_gssapi_helper_filter_creds(ssh_gssapi_client *client,
    u_int filter_flags, const char **services, u_int nservices)
{
	struct sshbuf *msg;
	u_int	       i;
	int	       r;

	(void)client;

	if (helper.fd == -1)
		return;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	if ((r = sshbuf_put_u8(msg,  SSH_GSSAPI_HLP_FILTER_CREDS)) != 0 ||
	    (r = sshbuf_put_u32(msg, filter_flags))                  != 0 ||
	    (r = sshbuf_put_u32(msg, nservices))                     != 0)
		fatal_fr(r, "compose FILTER_CREDS header");
	for (i = 0; i < nservices; i++) {
		if ((r = sshbuf_put_cstring(msg, services[i])) != 0)
			fatal_fr(r, "compose service");
	}

	helper_send(msg);
	sshbuf_reset(msg);
	helper_recv(msg); /* best-effort; error already logged by helper */
	sshbuf_free(msg);
}

/* ------------------------------------------------------------------ *
 * handoff — ccache is ready; release helper handle and exit helper.
 * ------------------------------------------------------------------ */
void
ssh_gssapi_helper_handoff(void)
{
	struct sshbuf *msg;
	int	       r;

	if (helper.fd == -1)
		return;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	if ((r = sshbuf_put_u8(msg, SSH_GSSAPI_HLP_HANDOFF)) != 0)
		fatal_fr(r, "compose HANDOFF");

	helper_send(msg);
	sshbuf_reset(msg);
	helper_recv(msg); /* wait for SUCCESS before closing the fd */
	sshbuf_free(msg);

	ssh_gssapi_helper_stop();
}

/* ------------------------------------------------------------------ *
 * vtable: cleanup — ask helper to destroy the ccache and exit.
 * ------------------------------------------------------------------ */
void
ssh_gssapi_helper_cleanup(void)
{
	struct sshbuf *msg;
	int	       r;

	if (helper.fd == -1)
		return;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	if ((r = sshbuf_put_u8(msg, SSH_GSSAPI_HLP_CLEANUP)) != 0)
		fatal_fr(r, "compose CLEANUP");

	helper_send(msg);
	sshbuf_reset(msg);
	helper_recv(msg); /* wait for SUCCESS before closing the fd */
	sshbuf_free(msg);

	ssh_gssapi_helper_stop();
}

#endif /* GSSAPI && KRB5 && !HEIMDAL && WITH_OPENSSL */
