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
 * sshd-gssapi-helper: out-of-process GSSAPI credential manager.
 *
 * Handles S4U2Self, S4U2Proxy, ccache management, and cleanup on behalf
 * of an authenticated sshd-session process.  Communicates via stdin/stdout
 * (a socketpair dup'd by the parent).
 *
 * Privilege model
 * ---------------
 * Starts as root so it can read the host Kerberos keytab.
 * After a successful IMPERSONATE it permanently drops to target_uid/gid
 * (seteuid/setegid) and remains there for all subsequent requests.
 *
 * State machine
 * -------------
 * ROOT state:   handles IMPERSONATE (requires keytab access)
 * USER state:   handles DELEGATE, FILTER_CREDS, CLEANUP
 *
 * If the parent (sshd-session) exits or closes the socket, poll() returns
 * POLLHUP / read() returns 0; cleanup_exit() destroys any live ccache.
 */

#include "includes.h"

#if defined(GSSAPI) && defined(KRB5) && !defined(HEIMDAL) && defined(WITH_OPENSSL)

#include <sys/types.h>

#include <errno.h>
#include <grp.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#ifdef HAVE_GSSAPI_H
# include <gssapi.h>
#elif defined(HAVE_GSSAPI_GSSAPI_H)
# include <gssapi/gssapi.h>
#endif
#ifdef HAVE_GSSAPI_KRB5_H
# include <gssapi_krb5.h>
#elif defined(HAVE_GSSAPI_GSSAPI_KRB5_H)
# include <gssapi/gssapi_krb5.h>
#endif
#ifdef HAVE_GSSAPI_GENERIC_H
# include <gssapi_generic.h>
#elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
# include <gssapi/gssapi_generic.h>
#endif
#include <krb5.h>

#include <openssl/evp.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "log.h"
#include "misc.h"
#include "atomicio.h"
#include "ssherr.h"
#include "crypto_api.h"

#include "sshd-gssapi-helper.h"
#include "gss-s4u-x509.h"

/* ------------------------------------------------------------------ *
 * Per-session state
 * ------------------------------------------------------------------ */
static struct {
	krb5_context	 krb5ctx;
	krb5_ccache	 ccache;
	gss_cred_id_t	 impersonated_cred;  /* held for S4U2Proxy */
	char		*ccache_envval;      /* "TYPE:name" */
	char		*ccache_filename;    /* bare path if FILE/DIR */
	uid_t		 target_uid;
	gid_t		 target_gid;
	int		 privs_dropped;
	int		 cleanup_pending;    /* CLEANUP received, drain then exit */
} st;

/* I/O queues (same pattern as ssh-pkcs11-helper) */
static struct sshbuf *iqueue;
static struct sshbuf *oqueue;

/* ------------------------------------------------------------------ *
 * Outgoing message helpers
 * ------------------------------------------------------------------ */
static void
send_msg(struct sshbuf *m)
{
	int r;

	if ((r = sshbuf_put_stringb(oqueue, m)) != 0)
		fatal_fr(r, "enqueue");
}

static void
send_success_empty(void)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	if ((r = sshbuf_put_u8(msg, SSH_GSSAPI_HLP_SUCCESS)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
}

static void
send_failure(void)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	if ((r = sshbuf_put_u8(msg, SSH_GSSAPI_HLP_FAILURE)) != 0)
		fatal_fr(r, "compose");
	send_msg(msg);
	sshbuf_free(msg);
}

/* ------------------------------------------------------------------ *
 * Log a GSSAPI major/minor status pair.
 * ------------------------------------------------------------------ */
static void
log_gss_error(OM_uint32 major, OM_uint32 minor, const char *where)
{
	OM_uint32	msg_ctx = 0, junk;
	gss_buffer_desc	status_string;

	do {
		gss_display_status(&junk, major, GSS_C_GSS_CODE,
		    GSS_C_NO_OID, &msg_ctx, &status_string);
		error("%s: %.*s", where,
		    (int)status_string.length, (char *)status_string.value);
		gss_release_buffer(&junk, &status_string);
	} while (msg_ctx != 0);

	msg_ctx = 0;
	do {
		gss_display_status(&junk, minor, GSS_C_MECH_CODE,
		    GSS_C_NO_OID, &msg_ctx, &status_string);
		error("%s (minor): %.*s", where,
		    (int)status_string.length, (char *)status_string.value);
		gss_release_buffer(&junk, &status_string);
	} while (msg_ctx != 0);
}

/* ------------------------------------------------------------------ *
 * IMPERSONATE
 *
 * This is the only handler that runs as root.  On success it
 * permanently drops to target_uid/gid.
 * ------------------------------------------------------------------ */
static void
process_impersonate(void)
{
	char		*user = NULL, *hostname = NULL;
	char		*auth_method = NULL, *client_address = NULL;
	char		*key_fingerprint = NULL;
	u_char		*sid_buf = NULL, *hpk_buf = NULL, *cpk_buf = NULL;
	size_t		 sid_len = 0, hpk_len = 0, cpk_len = 0;
	uint32_t	 lifetime_u32, target_uid_u32, target_gid_u32;
	struct sshkey	*host_pubkey = NULL, *client_key = NULL;
	struct sshbuf	*sid_sshbuf = NULL;
	int		 r, fips_mode;

	/* GSSAPI state for this handler */
	OM_uint32	 major, minor, junk;
	gss_OID_set	 oidset = GSS_C_NO_OID_SET;
	gss_name_t	 host_name = GSS_C_NO_NAME;
	gss_name_t	 user_name = GSS_C_NO_NAME;
	gss_cred_id_t	 host_creds = GSS_C_NO_CREDENTIAL;
	gss_buffer_desc	 gssbuf, displayname = GSS_C_EMPTY_BUFFER;
	char		*val = NULL;

	/* krb5 state for realm + keytab key retrieval */
	krb5_context	 kctx = NULL;
	unsigned char	*ikm = NULL;
	size_t		 ikm_len = 0;
	krb5_enctype	 enctype = 0;
	uint32_t	 kvno = 0;
	char		 realm_buf[256];
	const char	*realm = NULL;

	/* Attestation cert */
	unsigned char	*cert_der = NULL;
	size_t		 cert_der_len = 0;
	int		 tried_x509 = 0;

	/* ccache creation */
	krb5_principal	 princ = NULL;
	krb5_error_code	 problem;
	const char	*cctype, *ccname;

	/* -- Parse request -- */
	if ((r = sshbuf_get_cstring(iqueue, &user, NULL))           != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &hostname, NULL))       != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &auth_method, NULL))    != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &client_address, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(iqueue, &key_fingerprint, NULL))!= 0 ||
	    (r = sshbuf_get_string(iqueue, &sid_buf, &sid_len))     != 0 ||
	    (r = sshbuf_get_string(iqueue, &hpk_buf, &hpk_len))     != 0 ||
	    (r = sshbuf_get_string(iqueue, &cpk_buf, &cpk_len))     != 0 ||
	    (r = sshbuf_get_u32(iqueue, &lifetime_u32))              != 0 ||
	    (r = sshbuf_get_u32(iqueue, &target_uid_u32))            != 0 ||
	    (r = sshbuf_get_u32(iqueue, &target_gid_u32))            != 0)
		fatal_fr(r, "parse IMPERSONATE");

	debug_f("IMPERSONATE user=%.100s hostname=%.100s method=%.32s",
	    user, hostname, auth_method);

	fips_mode = EVP_default_properties_is_fips_enabled(NULL);

	/* Reconstruct host public key */
	if (hpk_len > 0 &&
	    (r = sshkey_from_blob(hpk_buf, hpk_len, &host_pubkey)) != 0) {
		error_fr(r, "host pubkey from blob");
		host_pubkey = NULL;
	}

	/* Reconstruct client auth key (may be absent) */
	if (cpk_len > 0 &&
	    (r = sshkey_from_blob(cpk_buf, cpk_len, &client_key)) != 0) {
		error_fr(r, "client key from blob");
		client_key = NULL;
	}

	/* In FIPS mode, Ed25519 client keys can't go into an X.509 SPKI */
	if (fips_mode && client_key != NULL &&
	    client_key->type == KEY_ED25519) {
		debug2_f("Ed25519 client key not usable in FIPS mode");
		sshkey_free(client_key);
		client_key = NULL;
	}

	/* Wrap session_id bytes in an sshbuf for the cert builder */
	if (sid_len > 0) {
		if ((sid_sshbuf = sshbuf_from(sid_buf, sid_len)) == NULL)
			fatal_f("sshbuf_from");
	} else {
		if ((sid_sshbuf = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new");
	}

	/* -- Step 1: acquire host creds from keytab -- */
	gss_create_empty_oid_set(&junk, &oidset);
	/* OID for Kerberos 5: 1.2.840.113554.1.2.2 */
	{
		static const gss_OID_desc krb5_oid = {
		    9, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"
		};
		gss_add_oid_set_member(&junk, (gss_OID)&krb5_oid, &oidset);
	}

	xasprintf(&val, "host@%s", hostname);
	gssbuf.value  = val;
	gssbuf.length = strlen(val);
	major = gss_import_name(&minor, &gssbuf,
	    GSS_C_NT_HOSTBASED_SERVICE, &host_name);
	free(val); val = NULL;
	if (GSS_ERROR(major)) {
		error_f("gss_import_name (host) failed");
		log_gss_error(major, minor, "IMPERSONATE: gss_import_name(host)");
		goto fail;
	}

	debug2_f("acquiring host credentials as uid=%u euid=%u",
	    (unsigned)getuid(), (unsigned)geteuid());

#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
	{
		char keytab_name[1024];

		keytab_name[0] = '\0';
		if (krb5_init_context(&kctx) == 0) {
			(void)krb5_kt_default_name(kctx, keytab_name,
			    sizeof(keytab_name));
		}
		if (keytab_name[0] == '\0')
			strlcpy(keytab_name, "FILE:/etc/krb5.keytab",
			    sizeof(keytab_name));

		gss_key_value_element_desc store_elements[] = {
			{ "client_keytab", keytab_name },
			{ "keytab",        keytab_name },
			{ "ccache",        "MEMORY:"   },
		};
		const gss_key_value_set_desc cred_store = { 3, store_elements };

		major = gss_acquire_cred_from(&minor, host_name,
		    (OM_uint32)lifetime_u32,
		    oidset, GSS_C_BOTH, &cred_store, &host_creds, NULL, NULL);
	}
#else
	major = gss_acquire_cred(&minor, host_name,
	    (OM_uint32)lifetime_u32,
	    oidset, GSS_C_BOTH, &host_creds, NULL, NULL);
#endif
	gss_release_name(&minor, &host_name);
	host_name = GSS_C_NO_NAME;

	if (GSS_ERROR(major)) {
		error_f("gss_acquire_cred(host@%s) failed", hostname);
		log_gss_error(major, minor,
		    "IMPERSONATE: gss_acquire_cred");
		goto fail;
	}

	/* -- Step 2: try X.509 attestation -- */
	realm_buf[0] = '\0';
	if (kctx == NULL)
		krb5_init_context(&kctx);

	if (kctx != NULL) {
		krb5_principal host_princ = NULL;

		if (krb5_sname_to_principal(kctx, hostname, "host",
		    KRB5_NT_SRV_HST, &host_princ) == 0) {
			const krb5_data *rd =
			    krb5_princ_realm(kctx, host_princ);
			if (rd && rd->data && rd->length > 0 &&
			    rd->length < sizeof(realm_buf)) {
				memcpy(realm_buf, rd->data, rd->length);
				realm_buf[rd->length] = '\0';
				realm = realm_buf;
			}
			krb5_free_principal(kctx, host_princ);
		}
	}

	if (realm != NULL && host_pubkey != NULL &&
	    ssh_gssapi_s4u_x509_get_keytab_key(kctx,
	        hostname, realm, fips_mode,
	        &ikm, &ikm_len, &enctype, &kvno) == 0) {
		tried_x509 = 1;
		if (ssh_gssapi_s4u_x509_build_cert(
		        user, realm, auth_method,
		        sid_sshbuf,
		        client_key,
		        key_fingerprint[0] ? key_fingerprint : NULL,
		        client_address[0]  ? client_address  : NULL,
		        host_pubkey,
		        ikm, ikm_len,
		        enctype, kvno,
		        hostname,
		        (u_int)lifetime_u32,
		        &cert_der, &cert_der_len) == 0) {
			gssbuf.value  = cert_der;
			gssbuf.length = cert_der_len;
			major = gss_import_name(&minor, &gssbuf,
			    GSS_KRB5_NT_X509_CERT, &user_name);
			free(cert_der); cert_der = NULL;
			if (GSS_ERROR(major)) {
				error_f("gss_import_name (X.509 cert) failed");
				log_gss_error(major, minor,
				    "IMPERSONATE: gss_import_name(cert)");
				gss_release_name(&minor, &user_name);
				user_name = GSS_C_NO_NAME;
			} else {
				debug_f("X.509 cert imported for user %.100s",
				    user);
			}
		}
	}

	freezero(ikm, ikm_len);
	ikm = NULL;

	if (tried_x509 && user_name == GSS_C_NO_NAME) {
		error_f("X.509 attestation failed for user %.100s;"
		    " S4U2Self skipped", user);
		goto fail;
	}

	/* -- Step 3: plain enterprise-name fallback -- */
	if (user_name == GSS_C_NO_NAME) {
		gssbuf.value  = (void *)user;
		gssbuf.length = strlen(user);
		major = gss_import_name(&minor, &gssbuf,
		    GSS_KRB5_NT_ENTERPRISE_NAME, &user_name);
		if (GSS_ERROR(major)) {
			error_f("gss_import_name (enterprise) failed");
			log_gss_error(major, minor,
			    "IMPERSONATE: gss_import_name(enterprise)");
			goto fail;
		}
	}

	/* -- Step 4: S4U2Self -- */
	debug2_f("calling gss_acquire_cred_impersonate_name for %.100s", user);
	major = gss_acquire_cred_impersonate_name(&minor,
	    host_creds, user_name, (OM_uint32)lifetime_u32,
	    oidset, GSS_C_INITIATE,
	    &st.impersonated_cred, NULL, NULL);

	gss_release_cred(&minor, &host_creds);
	host_creds = GSS_C_NO_CREDENTIAL;
	gss_release_oid_set(&junk, &oidset);
	oidset = GSS_C_NO_OID_SET;

	if (GSS_ERROR(major)) {
		error_f("gss_acquire_cred_impersonate_name failed for %.100s",
		    user);
		log_gss_error(major, minor,
		    "IMPERSONATE: gss_acquire_cred_impersonate_name");
		gss_release_name(&minor, &user_name);
		goto fail;
	}

	gss_release_name(&minor, &user_name);
	user_name = GSS_C_NO_NAME;

	/* Obtain the KDC-canonicalised principal name for ccache init */
	major = gss_inquire_cred(&minor, st.impersonated_cred,
	    &user_name, NULL, NULL, NULL);
	if (GSS_ERROR(major)) {
		error_f("gss_inquire_cred failed");
		log_gss_error(major, minor, "IMPERSONATE: gss_inquire_cred");
		goto fail;
	}
	major = gss_display_name(&minor, user_name, &displayname, NULL);
	gss_release_name(&minor, &user_name);
	user_name = GSS_C_NO_NAME;
	if (GSS_ERROR(major)) {
		error_f("gss_display_name failed");
		log_gss_error(major, minor, "IMPERSONATE: gss_display_name");
		goto fail;
	}

	debug2_f("S4U2Self succeeded for %.100s (canonical: %.*s)",
	    user, (int)displayname.length, (char *)displayname.value);

	/*
	 * -- Step 5: permanently drop to target user --
	 *
	 * Use setuid()/setgid() rather than seteuid()/setegid() so that the
	 * real UID is also changed.  This matters for credential-storage back-
	 * ends that authenticate via real UID:
	 *
	 *  KEYRING:persistent — KEYCTL_GET_PERSISTENT(uid) requires either
	 *    real_uid == uid  OR  CAP_SETUID in the effective capability set.
	 *    seteuid() clears all effective capabilities when transitioning
	 *    from euid=0 to euid≠0, so KEYCTL_GET_PERSISTENT(target_uid)
	 *    would fail with EPERM.  setuid() sets real_uid = target_uid,
	 *    satisfying the identity check without needing CAP_SETUID.
	 *
	 *  KCM (SSSD-KCM) — uses SO_PEERCRED which returns real_uid.  With
	 *    seteuid(), real_uid stays 0 so SSSD-KCM would place the ccache
	 *    in the root collection rather than the user's collection.
	 *
	 * Call order: initgroups → setgid → setuid (standard privilege-drop
	 * sequence; setgid must precede setuid while we still have privilege).
	 */
	if (initgroups(user, (gid_t)target_gid_u32) == -1)
		error_f("initgroups(%s, %u): %s (continuing)",
		    user, target_gid_u32, strerror(errno));
	if (setgid((gid_t)target_gid_u32) == -1 ||
	    setuid((uid_t)target_uid_u32) == -1) {
		error_f("setuid(%u/%u): %s",
		    target_gid_u32, target_uid_u32, strerror(errno));
		goto fail;
	}
	st.target_uid    = (uid_t)target_uid_u32;
	st.target_gid    = (gid_t)target_gid_u32;
	st.privs_dropped = 1;

	/* -- Step 6: create user ccache and copy the evidence ticket -- */
	if (st.krb5ctx == NULL) {
		if ((problem = krb5_init_context(&st.krb5ctx)) != 0) {
			error_f("krb5_init_context: %s",
			    krb5_get_error_message(st.krb5ctx, problem));
			goto fail;
		}
	}

	{
		/*
		 * krb5_cc_new_unique() wants the bare ccache type ("KCM",
		 * "FILE", …).  Resolve the default ccache name to obtain a
		 * handle, use krb5_cc_get_type() to extract the type string,
		 * then create a new unique ccache of that type.
		 */
		krb5_ccache    tmp_cc = NULL;
		char           cctype_buf[64];
		size_t         cctype_len;

		if ((problem = krb5_cc_resolve(st.krb5ctx,
		    krb5_cc_default_name(st.krb5ctx), &tmp_cc)) != 0) {
			error_f("krb5_cc_resolve(%s): %s",
			    krb5_cc_default_name(st.krb5ctx),
			    krb5_get_error_message(st.krb5ctx, problem));
			goto fail;
		}
		/*
		 * krb5_cc_get_type() returns the bare type name ("KCM", "FILE").
		 * Some MIT KRB5 builds include a trailing colon; strip it so
		 * krb5_cc_new_unique() can find the type in its ops table.
		 */
		strlcpy(cctype_buf, krb5_cc_get_type(st.krb5ctx, tmp_cc),
		    sizeof(cctype_buf));
		krb5_cc_close(st.krb5ctx, tmp_cc);
		cctype_len = strlen(cctype_buf);
		if (cctype_len > 0 && cctype_buf[cctype_len - 1] == ':')
			cctype_buf[cctype_len - 1] = '\0';

		if ((problem = krb5_cc_new_unique(st.krb5ctx,
		    cctype_buf, NULL, &st.ccache)) != 0) {
			error_f("krb5_cc_new_unique (type=%s): %s",
			    cctype_buf,
			    krb5_get_error_message(st.krb5ctx, problem));
			goto fail;
		}
	}

	if ((problem = krb5_parse_name(st.krb5ctx,
	    (char *)displayname.value, &princ)) != 0 ||
	    (problem = krb5_cc_initialize(st.krb5ctx,
	    st.ccache, princ)) != 0) {
		const char *msg = krb5_get_error_message(st.krb5ctx, problem);
		error_f("krb5 ccache init failed: %s", msg);
		krb5_free_error_message(st.krb5ctx, msg);
		if (princ != NULL)
			krb5_free_principal(st.krb5ctx, princ);
		goto fail;
	}
	krb5_free_principal(st.krb5ctx, princ);
	princ = NULL;

	{
		OM_uint32 copy_major, copy_minor;
		copy_major = gss_krb5_copy_ccache(&copy_minor,
		    st.impersonated_cred, st.ccache);
		if (copy_major != GSS_S_COMPLETE) {
			error_f("gss_krb5_copy_ccache failed");
			log_gss_error(copy_major, copy_minor,
			    "IMPERSONATE: gss_krb5_copy_ccache");
			goto fail;
		}
	}

	cctype = krb5_cc_get_type(st.krb5ctx, st.ccache);
	ccname = krb5_cc_get_name(st.krb5ctx, st.ccache);
	xasprintf(&st.ccache_envval, "%s:%s", cctype, ccname);
	if (strcmp(cctype, "FILE") == 0 || strcmp(cctype, "DIR") == 0)
		st.ccache_filename = xstrdup(ccname);

	gss_release_buffer(&minor, &displayname);

	/* -- Reply -- */
	{
		struct sshbuf *msg;
		int rr;

		if ((msg = sshbuf_new()) == NULL)
			fatal_f("sshbuf_new");
		if ((rr = sshbuf_put_u8(msg, SSH_GSSAPI_HLP_SUCCESS))         != 0 ||
		    (rr = sshbuf_put_cstring(msg, st.ccache_envval))           != 0 ||
		    (rr = sshbuf_put_cstring(msg,
		        st.ccache_filename ? st.ccache_filename : ""))         != 0 ||
		    (rr = sshbuf_put_u8(msg, 1 /* set KRB5CCNAME */))          != 0)
			fatal_fr(rr, "compose IMPERSONATE reply");
		send_msg(msg);
		sshbuf_free(msg);
	}

	debug_f("ccache created: %s", st.ccache_envval);
	goto cleanup;

fail:
	gss_release_buffer(&minor, &displayname);
	if (st.impersonated_cred != GSS_C_NO_CREDENTIAL) {
		gss_release_cred(&minor, &st.impersonated_cred);
		st.impersonated_cred = GSS_C_NO_CREDENTIAL;
	}
	if (st.ccache != NULL && st.krb5ctx != NULL) {
		krb5_cc_destroy(st.krb5ctx, st.ccache);
		st.ccache = NULL;
	}
	send_failure();

cleanup:
	/* These were never transferred to st */
	if (host_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&minor, &host_creds);
	if (oidset != GSS_C_NO_OID_SET)
		gss_release_oid_set(&junk, &oidset);
	if (host_name != GSS_C_NO_NAME)
		gss_release_name(&minor, &host_name);
	if (user_name != GSS_C_NO_NAME)
		gss_release_name(&minor, &user_name);
	if (kctx != NULL)
		krb5_free_context(kctx);
	sshkey_free(host_pubkey);
	sshkey_free(client_key);
	sshbuf_free(sid_sshbuf);
	free(user); free(hostname); free(auth_method);
	free(client_address); free(key_fingerprint);
	free(sid_buf); free(hpk_buf); free(cpk_buf);
	free(cert_der);
	freezero(ikm, ikm_len);
}

/* ------------------------------------------------------------------ *
 * DELEGATE — S4U2Proxy for each listed service.
 * Runs as target_uid (privs already dropped by IMPERSONATE).
 * ------------------------------------------------------------------ */
static void
process_delegate(void)
{
	OM_uint32	 major, minor;
	gss_buffer_desc	 service_buf, output_token = GSS_C_EMPTY_BUFFER;
	gss_name_t	 target_name;
	gss_ctx_id_t	 ctx;
	uint32_t	 nservices, lifetime_u32, i;
	char		*service = NULL;
	int		 r;

	if ((r = sshbuf_get_u32(iqueue, &nservices)) != 0)
		fatal_fr(r, "parse nservices");
	if (nservices > 256) {
		error_f("too many services (%u)", nservices);
		/* drain remaining fields as best we can */
		send_failure();
		return;
	}

	if (!st.privs_dropped ||
	    st.impersonated_cred == GSS_C_NO_CREDENTIAL ||
	    st.ccache_envval == NULL) {
		error_f("DELEGATE before successful IMPERSONATE");
		/* drain */
		for (i = 0; i < nservices; i++) {
			free(service); service = NULL;
			sshbuf_get_cstring(iqueue, &service, NULL);
		}
		free(service);
		sshbuf_get_u32(iqueue, &lifetime_u32);
		send_failure();
		return;
	}

	/* Point the GSSAPI library at the user's ccache */
	setenv("KRB5CCNAME", st.ccache_envval, 1);

	for (i = 0; i < nservices; i++) {
		service = NULL;
		if ((r = sshbuf_get_cstring(iqueue, &service, NULL)) != 0)
			fatal_fr(r, "parse service");

		ctx	      = GSS_C_NO_CONTEXT;
		target_name = GSS_C_NO_NAME;

		service_buf.value  = service;
		service_buf.length = strlen(service);

		major = gss_import_name(&minor, &service_buf,
		    GSS_C_NO_OID, &target_name);
		if (GSS_ERROR(major)) {
			error_f("gss_import_name failed for %.200s", service);
			free(service);
			continue;
		}

		major = gss_init_sec_context(&minor,
		    st.impersonated_cred,
		    &ctx, target_name,
		    GSS_C_NO_OID,
		    0, lifetime_u32,
		    GSS_C_NO_CHANNEL_BINDINGS,
		    GSS_C_NO_BUFFER,
		    NULL, &output_token, NULL, NULL);

		gss_release_buffer(&minor, &output_token);
		gss_release_name(&minor, &target_name);
		if (ctx != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);

		if (GSS_ERROR(major))
			error_f("S4U2Proxy for %.200s failed", service);
		else
			debug2_f("S4U2Proxy ticket obtained for %.200s", service);

		free(service);
	}

	if ((r = sshbuf_get_u32(iqueue, &lifetime_u32)) != 0)
		fatal_fr(r, "parse lifetime");

	/* Flush proxy tickets into KRB5CCNAME ccache */
	major = gss_store_cred(&minor, st.impersonated_cred,
	    GSS_C_INITIATE, GSS_C_NO_OID, 1, 1, NULL, NULL);
	if (GSS_ERROR(major))
		error_f("gss_store_cred failed; proxy tickets may be missing");

	unsetenv("KRB5CCNAME");
	send_success_empty();
}

/* ------------------------------------------------------------------ *
 * FILTER_CREDS — remove unwanted ticket classes from the ccache.
 * ------------------------------------------------------------------ */
static void
process_filter_creds(void)
{
	uint32_t	 filter_flags, nservices, i;
	char	       **services = NULL;
	int		 r;

	if ((r = sshbuf_get_u32(iqueue, &filter_flags)) != 0 ||
	    (r = sshbuf_get_u32(iqueue, &nservices))    != 0)
		fatal_fr(r, "parse FILTER_CREDS header");
	if (nservices > 256) {
		error_f("too many services (%u)", nservices);
		send_failure();
		return;
	}

	services = xcalloc(nservices + 1, sizeof(*services));
	for (i = 0; i < nservices; i++) {
		if ((r = sshbuf_get_cstring(iqueue,
		    &services[i], NULL)) != 0)
			fatal_fr(r, "parse service");
	}

	if (st.krb5ctx == NULL || st.ccache == NULL ||
	    st.ccache_envval == NULL) {
		error_f("FILTER_CREDS before successful IMPERSONATE");
		send_failure();
		goto out;
	}

	/*
	 * Delegate to the shared filter implementation in gss-serv-krb5.c.
	 * That function is compiled into the helper via GSSHELPER_OBJS
	 * through gss-serv-krb5.o — but gss-serv-krb5.c has dependencies on
	 * sshd internals (the_authctxt, options).  We inline the filter logic
	 * here to keep the helper self-contained.
	 */
	{
		krb5_cc_cursor cursor;
		krb5_creds    *keep = NULL;
		krb5_principal helper_princ = NULL;
		u_int nkeep = 0, cap = 0;

		if (krb5_cc_get_principal(st.krb5ctx, st.ccache,
		    &helper_princ) != 0 ||
		    krb5_cc_start_seq_get(st.krb5ctx, st.ccache,
		    &cursor) != 0) {
			error_f("cannot enumerate ccache");
			send_failure();
			if (helper_princ)
				krb5_free_principal(st.krb5ctx, helper_princ);
			goto out;
		}

		krb5_creds cred;
		char *srvname;
		int is_tgt, is_proxy, drop;

		while (krb5_cc_next_cred(st.krb5ctx, st.ccache,
		    &cursor, &cred) == 0) {
			is_tgt = is_proxy = 0;
			if (krb5_unparse_name(st.krb5ctx, cred.server,
			    &srvname) == 0) {
				is_tgt = strncmp(srvname, "krbtgt/", 7) == 0;
				krb5_free_unparsed_name(st.krb5ctx, srvname);
			}
			if (!is_tgt) {
				krb5_principal svc_princ;
				for (i = 0; i < nservices; i++) {
					if (krb5_parse_name(st.krb5ctx,
					    services[i], &svc_princ) != 0)
						continue;
					if (krb5_principal_compare(st.krb5ctx,
					    cred.server, svc_princ))
						is_proxy = 1;
					krb5_free_principal(st.krb5ctx, svc_princ);
					if (is_proxy) break;
				}
			}

			if (is_tgt)
				drop = filter_flags &
				    SSH_GSSAPI_HLP_FILTER_TGT;
			else if (is_proxy)
				drop = filter_flags &
				    SSH_GSSAPI_HLP_FILTER_PROXY;
			else
				drop = filter_flags &
				    SSH_GSSAPI_HLP_FILTER_SELF;

			if (!drop) {
				if (nkeep >= cap) {
					cap = cap ? cap * 2 : 4;
					keep = xreallocarray(keep, cap,
					    sizeof(*keep));
				}
				keep[nkeep++] = cred;
			} else
				krb5_free_cred_contents(st.krb5ctx, &cred);
		}
		krb5_cc_end_seq_get(st.krb5ctx, st.ccache, &cursor);

		if (krb5_cc_initialize(st.krb5ctx, st.ccache,
		    helper_princ) == 0) {
			for (i = 0; i < nkeep; i++)
				krb5_cc_store_cred(st.krb5ctx, st.ccache,
				    &keep[i]);
			debug_f("ccache filter 0x%x: retained %u ticket(s)",
			    filter_flags, nkeep);
		}
		for (i = 0; i < nkeep; i++)
			krb5_free_cred_contents(st.krb5ctx, &keep[i]);
		free(keep);
		krb5_free_principal(st.krb5ctx, helper_princ);
	}

	send_success_empty();
out:
	for (i = 0; i < nservices; i++) free(services[i]);
	free(services);
}

/* ------------------------------------------------------------------ *
 * HANDOFF — release creds, close (do NOT destroy) the ccache, exit.
 *
 * Called when all credential operations are complete and the ccache
 * has been handed to the user session via KRB5CCNAME.  The ccache
 * persists in the user's keyring/KCM/filesystem; the helper is no
 * longer needed and exits immediately after replying SUCCESS.
 * ------------------------------------------------------------------ */
static void
process_handoff(void)
{
	OM_uint32 minor;

	debug_f("handing off ccache to session");

	if (st.impersonated_cred != GSS_C_NO_CREDENTIAL) {
		gss_release_cred(&minor, &st.impersonated_cred);
		st.impersonated_cred = GSS_C_NO_CREDENTIAL;
	}
	/*
	 * Close the ccache handle without destroying the ccache contents.
	 * krb5_cc_close() releases the local handle only; the ccache
	 * (keyring entry, KCM record, or file) persists for the session.
	 */
	if (st.ccache != NULL && st.krb5ctx != NULL) {
		krb5_cc_close(st.krb5ctx, st.ccache);
		st.ccache = NULL;
	}
	send_success_empty();
	st.cleanup_pending = 1;
}

/* ------------------------------------------------------------------ *
 * CLEANUP — destroy the ccache, then (after draining oqueue) exit.
 * ------------------------------------------------------------------ */
static void
process_cleanup(void)
{
	OM_uint32 minor;

	if (st.impersonated_cred != GSS_C_NO_CREDENTIAL) {
		gss_release_cred(&minor, &st.impersonated_cred);
		st.impersonated_cred = GSS_C_NO_CREDENTIAL;
	}
	if (st.ccache != NULL && st.krb5ctx != NULL) {
		krb5_cc_destroy(st.krb5ctx, st.ccache);
		st.ccache = NULL;
	}
	if (st.krb5ctx != NULL) {
		krb5_free_context(st.krb5ctx);
		st.krb5ctx = NULL;
	}
	free(st.ccache_envval);  st.ccache_envval  = NULL;
	free(st.ccache_filename); st.ccache_filename = NULL;

	send_success_empty();
	st.cleanup_pending = 1;
}

/* ------------------------------------------------------------------ *
 * Main dispatch — called from the poll loop when a full message is
 * available in iqueue.
 * ------------------------------------------------------------------ */
static void
process(void)
{
	u_char		 type;
	u_int		 msg_len, buf_len, consumed;
	const u_char	*cp;
	int		 r;

	buf_len = sshbuf_len(iqueue);
	if (buf_len < 5)
		return;
	cp = sshbuf_ptr(iqueue);
	msg_len = get_u32(cp);
	if (msg_len > SSH_GSSAPI_HLP_MAX_MSG) {
		error("bad message len %u", msg_len);
		cleanup_exit(11);
	}
	if (buf_len < msg_len + 4)
		return; /* incomplete */
	if ((r = sshbuf_consume(iqueue, 4)) != 0 ||
	    (r = sshbuf_get_u8(iqueue, &type)) != 0)
		fatal_fr(r, "parse header");
	buf_len -= 4;

	switch (type) {
	case SSH_GSSAPI_HLP_IMPERSONATE:
		debug("process_impersonate");
		process_impersonate();
		break;
	case SSH_GSSAPI_HLP_DELEGATE:
		debug("process_delegate");
		process_delegate();
		break;
	case SSH_GSSAPI_HLP_FILTER_CREDS:
		debug("process_filter_creds");
		process_filter_creds();
		break;
	case SSH_GSSAPI_HLP_HANDOFF:
		debug("process_handoff");
		process_handoff();
		break;
	case SSH_GSSAPI_HLP_CLEANUP:
		debug("process_cleanup");
		process_cleanup();
		break;
	default:
		error("unknown message type %u", type);
		break;
	}

	/* Discard any unconsumed bytes from this message */
	consumed = buf_len - sshbuf_len(iqueue);
	if (msg_len > consumed) {
		if ((r = sshbuf_consume(iqueue,
		    msg_len - consumed)) != 0)
			fatal_fr(r, "consume tail");
	}
}

/* ------------------------------------------------------------------ *
 * Cleanup on exit — always try to destroy the ccache.
 * ------------------------------------------------------------------ */
void
cleanup_exit(int i)
{
	OM_uint32 minor;

	if (st.impersonated_cred != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&minor, &st.impersonated_cred);
	if (st.ccache != NULL && st.krb5ctx != NULL)
		krb5_cc_destroy(st.krb5ctx, st.ccache);
	_exit(i);
}

/* ------------------------------------------------------------------ *
 * main
 * ------------------------------------------------------------------ */
int
main(int argc, char **argv)
{
	int		 in, out, ch;
	ssize_t		 len;
	SyslogFacility	 log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel	 log_level    = SYSLOG_LEVEL_ERROR;
	char		 buf[4 * 4096];
	struct pollfd	 pfd[2];
	extern char	*__progname;

	__progname = ssh_get_progname(argv[0]);
	seed_rng();

	log_init(__progname, log_level, log_facility, 0);

	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			if (log_level == SYSLOG_LEVEL_ERROR)
				log_level = SYSLOG_LEVEL_DEBUG1;
			else if (log_level < SYSLOG_LEVEL_DEBUG3)
				log_level++;
			break;
		default:
			fprintf(stderr, "usage: %s [-v]\n", __progname);
			exit(1);
		}
	}
	/*
	 * Always log to syslog (log_stderr stays 0).  When spawned by
	 * sshd-session the helper's inherited stderr fd goes to /dev/null,
	 * so enabling log_stderr would silently discard all messages.
	 * Syslog messages reach journald regardless of the stderr fd.
	 */
	log_init(__progname, log_level, log_facility, 0);

	in  = STDIN_FILENO;
	out = STDOUT_FILENO;

	memset(&st, 0, sizeof(st));
	st.impersonated_cred = GSS_C_NO_CREDENTIAL;

	if ((iqueue = sshbuf_new()) == NULL ||
	    (oqueue = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");

	for (;;) {
		int r;

		memset(pfd, 0, sizeof(pfd));
		pfd[0].fd = in;
		pfd[1].fd = out;

		if ((r = sshbuf_check_reserve(iqueue, sizeof(buf))) == 0 &&
		    (r = sshbuf_check_reserve(oqueue,
		        SSH_GSSAPI_HLP_MAX_MSG)) == 0)
			pfd[0].events = POLLIN;
		else if (r != SSH_ERR_NO_BUFFER_SPACE)
			fatal_fr(r, "reserve");

		if (sshbuf_len(oqueue) > 0)
			pfd[1].events = POLLOUT;

		if ((r = poll(pfd, 2, -1)) <= 0) {
			if (r == 0 || errno == EINTR)
				continue;
			fatal("poll: %s", strerror(errno));
		}

		if (pfd[0].revents & (POLLIN | POLLHUP | POLLERR)) {
			len = read(in, buf, sizeof(buf));
			if (len == 0) {
				debug("EOF from sshd — exiting");
				cleanup_exit(0);
			} else if (len < 0) {
				error("read: %s", strerror(errno));
				cleanup_exit(1);
			} else if ((r = sshbuf_put(iqueue, buf, len)) != 0)
				fatal_fr(r, "sshbuf_put");
		}

		if (pfd[1].revents & (POLLOUT | POLLHUP)) {
			len = write(out, sshbuf_ptr(oqueue),
			    sshbuf_len(oqueue));
			if (len < 0) {
				error("write: %s", strerror(errno));
				cleanup_exit(1);
			} else if ((r = sshbuf_consume(oqueue, len)) != 0)
				fatal_fr(r, "consume");
			/* Exit cleanly after the CLEANUP reply is flushed */
			if (st.cleanup_pending &&
			    sshbuf_len(oqueue) == 0)
				cleanup_exit(0);
		}

		if (sshbuf_check_reserve(oqueue,
		    SSH_GSSAPI_HLP_MAX_MSG) == 0)
			process();
	}
	/* NOTREACHED */
}

#else /* !(GSSAPI && KRB5 && !HEIMDAL && WITH_OPENSSL) */

#include <stdio.h>
#include <stdlib.h>
#include "log.h"
#include "misc.h"

void cleanup_exit(int i) { _exit(i); }

int
main(int argc, char **argv)
{
	extern char *__progname;
	__progname = ssh_get_progname(argv[0]);
	log_init(__progname, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);
	fatal("GSSAPI/Kerberos/OpenSSL support disabled at compile time");
}
#endif /* GSSAPI && KRB5 && !HEIMDAL && WITH_OPENSSL */
