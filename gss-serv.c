/* $OpenBSD: gss-serv.c,v 1.33 2025/09/29 21:30:15 dtucker Exp $ */

/*
 * Copyright (c) 2001-2009 Simon Wilkinson. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
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

#include "includes.h"

#ifdef GSSAPI

#include <sys/types.h>
#include <sys/param.h>

#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "openbsd-compat/sys-queue.h"
#include "xmalloc.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#include "log.h"
#include "channels.h"
#include "session.h"
#include "misc.h"
#include "servconf.h"
#include "uidswap.h"

#include "ssh-gss.h"
#include "monitor_wrap.h"
#include "packet.h"
#include "kex.h"

#include "sshbuf.h"

#ifdef KRB5
# include <krb5.h>
#endif
#if defined(KRB5) && !defined(HEIMDAL) && defined(WITH_OPENSSL)
# ifdef HAVE_GSSAPI_KRB5_H
#  include <gssapi_krb5.h>
# elif defined(HAVE_GSSAPI_GSSAPI_KRB5_H)
#  include <gssapi/gssapi_krb5.h>
# endif
# include <openssl/evp.h>
# include "gss-s4u-x509.h"
#endif

extern ServerOptions options;

static ssh_gssapi_client gssapi_client =
    { GSS_C_EMPTY_BUFFER, GSS_C_EMPTY_BUFFER, GSS_C_NO_CREDENTIAL,
    GSS_C_NO_NAME, NULL, {NULL, NULL, NULL, NULL, NULL}, 0, 0, NULL, 0};

ssh_gssapi_mech gssapi_null_mech =
    { NULL, NULL, {0, NULL}, NULL, NULL, NULL, NULL, NULL};

#ifdef KRB5
extern ssh_gssapi_mech gssapi_kerberos_mech;
#endif

ssh_gssapi_mech* supported_mechs[]= {
#ifdef KRB5
	&gssapi_kerberos_mech,
#endif
	&gssapi_null_mech,
};

/*
 * ssh_gssapi_supported_oids() can cause sandbox violations, so prepare the
 * list of supported mechanisms before privsep is set up.
 */
static gss_OID_set supported_oids;

void
ssh_gssapi_prepare_supported_oids(void)
{
	ssh_gssapi_supported_oids(&supported_oids);
}

OM_uint32
ssh_gssapi_test_oid_supported(OM_uint32 *ms, gss_OID member, int *present)
{
	if (supported_oids == NULL)
		ssh_gssapi_prepare_supported_oids();
	return gss_test_oid_set_member(ms, member, supported_oids, present);
}

/*
 * Acquire credentials for a server running on the current host.
 * Requires that the context structure contains a valid OID
 */

/* Returns a GSSAPI error code */
/* Privileged (called from ssh_gssapi_server_ctx) */
static OM_uint32
ssh_gssapi_acquire_cred(Gssctxt *ctx)
{
	OM_uint32 status;
	char lname[NI_MAXHOST];
	gss_OID_set oidset;

	if (options.gss_strict_acceptor) {
		gss_create_empty_oid_set(&status, &oidset);
		gss_add_oid_set_member(&status, ctx->oid, &oidset);

		if (gethostname(lname, HOST_NAME_MAX)) {
			gss_release_oid_set(&status, &oidset);
			return (-1);
		}

		if (GSS_ERROR(ssh_gssapi_import_name(ctx, lname))) {
			gss_release_oid_set(&status, &oidset);
			return (ctx->major);
		}

		if ((ctx->major = gss_acquire_cred(&ctx->minor,
		    ctx->name, 0, oidset, GSS_C_ACCEPT, &ctx->creds,
		    NULL, NULL)))
			ssh_gssapi_error(ctx);

		gss_release_oid_set(&status, &oidset);
		return (ctx->major);
	} else {
		ctx->name = GSS_C_NO_NAME;
		ctx->creds = GSS_C_NO_CREDENTIAL;
	}
	return GSS_S_COMPLETE;
}

/* Privileged */
OM_uint32
ssh_gssapi_server_ctx(Gssctxt **ctx, gss_OID oid)
{
	if (*ctx)
		ssh_gssapi_delete_ctx(ctx);
	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	return (ssh_gssapi_acquire_cred(*ctx));
}

/* Unprivileged */
char *
ssh_gssapi_server_mechanisms(void) {
	if (supported_oids == NULL)
		ssh_gssapi_prepare_supported_oids();
	return (ssh_gssapi_kex_mechs(supported_oids,
	    &ssh_gssapi_server_check_mech, NULL, NULL,
	    options.gss_kex_algorithms));
}

/* Unprivileged */
int
ssh_gssapi_server_check_mech(Gssctxt **dum, gss_OID oid, const char *data,
    const char *dummy) {
	Gssctxt *ctx = NULL;
	int res;

	res = !GSS_ERROR(mm_ssh_gssapi_server_ctx(&ctx, oid));
	ssh_gssapi_delete_ctx(&ctx);

	return (res);
}

/* Unprivileged */
void
ssh_gssapi_supported_oids(gss_OID_set *oidset)
{
	int i = 0;
	OM_uint32 min_status;
	int present;
	gss_OID_set supported;

	gss_create_empty_oid_set(&min_status, oidset);

	if (GSS_ERROR(gss_indicate_mechs(&min_status, &supported)))
		return;

	while (supported_mechs[i]->name != NULL) {
		if (GSS_ERROR(gss_test_oid_set_member(&min_status,
		    &supported_mechs[i]->oid, supported, &present)))
			present = 0;
		if (present)
			gss_add_oid_set_member(&min_status,
			    &supported_mechs[i]->oid, oidset);
		i++;
	}

	gss_release_oid_set(&min_status, &supported);
}


/* Wrapper around accept_sec_context
 * Requires that the context contains:
 *    oid
 *    credentials	(from ssh_gssapi_acquire_cred)
 */
/* Privileged */
OM_uint32
ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *recv_tok,
    gss_buffer_desc *send_tok, OM_uint32 *flags)
{
	OM_uint32 status;
	gss_OID mech;

	ctx->major = gss_accept_sec_context(&ctx->minor,
	    &ctx->context, ctx->creds, recv_tok,
	    GSS_C_NO_CHANNEL_BINDINGS, &ctx->client, &mech,
	    send_tok, flags, NULL, &ctx->client_creds);

	if (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	if (ctx->client_creds)
		debug("Received some client credentials");
	else
		debug("Got no client credentials");

	status = ctx->major;

	/* Now, if we're complete and we have the right flags, then
	 * we flag the user as also having been authenticated
	 */

	if (((flags == NULL) || ((*flags & GSS_C_MUTUAL_FLAG) &&
	    (*flags & GSS_C_INTEG_FLAG))) && (ctx->major == GSS_S_COMPLETE)) {
		if (ssh_gssapi_getclient(ctx, &gssapi_client))
			fatal("Couldn't convert client name");
	}

	return (status);
}

/*
 * This parses an exported name, extracting the mechanism specific portion
 * to use for ACL checking. It verifies that the name belongs the mechanism
 * originally selected.
 */
static OM_uint32
ssh_gssapi_parse_ename(Gssctxt *ctx, gss_buffer_t ename, gss_buffer_t name)
{
	u_char *tok;
	OM_uint32 offset;
	OM_uint32 oidl;

	tok = ename->value;

	/*
	 * Check that ename is long enough for all of the fixed length
	 * header, and that the initial ID bytes are correct
	 */

	if (ename->length < 6 || memcmp(tok, "\x04\x01", 2) != 0)
		return GSS_S_FAILURE;

	/*
	 * Extract the OID, and check it. Here GSSAPI breaks with tradition
	 * and does use the OID type and length bytes. To confuse things
	 * there are two lengths - the first including these, and the
	 * second without.
	 */

	oidl = get_u16(tok+2); /* length including next two bytes */
	oidl = oidl-2; /* turn it into the _real_ length of the variable OID */

	/*
	 * Check the BER encoding for correct type and length, that the
	 * string is long enough and that the OID matches that in our context
	 */
	if (tok[4] != 0x06 || tok[5] != oidl ||
	    ename->length < oidl+6 ||
	    !ssh_gssapi_check_oid(ctx, tok+6, oidl))
		return GSS_S_FAILURE;

	offset = oidl+6;

	if (ename->length < offset+4)
		return GSS_S_FAILURE;

	name->length = get_u32(tok+offset);
	offset += 4;

	if (UINT_MAX - offset < name->length)
		return GSS_S_FAILURE;
	if (ename->length < offset+name->length)
		return GSS_S_FAILURE;

	name->value = xmalloc(name->length+1);
	memcpy(name->value, tok+offset, name->length);
	((char *)name->value)[name->length] = 0;

	return GSS_S_COMPLETE;
}


/* Extract authentication indicators from the Kerberos ticket. Authentication
 * indicators are GSSAPI name attributes for the name "auth-indicators".
 * Multiple indicators might be present in the ticket.
 * Each indicator is an utf8 string. */

#define AUTH_INDICATORS_TAG "auth-indicators"
#define SSH_GSSAPI_MAX_INDICATORS 64

/* Privileged (called from accept_secure_ctx) */
static OM_uint32
ssh_gssapi_getindicators(Gssctxt *ctx, gss_name_t gss_name, ssh_gssapi_client *client)
{
	gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
	gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc display_value = GSS_C_EMPTY_BUFFER;
	int is_mechname, authenticated, complete, more;
	size_t count, i;

	ctx->major = gss_inquire_name(&ctx->minor, gss_name,
				      &is_mechname, NULL, &attrs);
	if (ctx->major != GSS_S_COMPLETE) {
		return (ctx->major);
	}

	if (attrs == GSS_C_NO_BUFFER_SET) {
		/* No indicators in the ticket */
		return (0);
	}

	client->indicators = NULL;
	count = 0;
	for (i = 0; i < attrs->count; i++) {
		authenticated = 0;
		complete = 0;
		more = -1;
		/* skip anything but auth-indicators */
		if (((sizeof(AUTH_INDICATORS_TAG) - 1) != attrs->elements[i].length) ||
		    memcmp(AUTH_INDICATORS_TAG,
			   attrs->elements[i].value,
			   sizeof(AUTH_INDICATORS_TAG) - 1) != 0)
			continue;
		/* retrieve all indicators */
		while (more != 0) {
			value.value = NULL;
			display_value.value = NULL;
			ctx->major = gss_get_name_attribute(&ctx->minor, gss_name,
							    &attrs->elements[i], &authenticated,
							    &complete, &value, &display_value, &more);
			if (ctx->major != GSS_S_COMPLETE)
				goto out;

			if ((value.value != NULL) && authenticated) {
				if (count >= SSH_GSSAPI_MAX_INDICATORS) {
					logit("ssh_gssapi_getindicators: too many "
					    "indicators, truncating at %d",
					    SSH_GSSAPI_MAX_INDICATORS);
					/* value/display_value released at out: */
					goto done;
				}

				client->indicators = xrecallocarray(client->indicators, count, count + 1, sizeof(char*));
				if (client->indicators == NULL) {
					fatal("ssh_gssapi_getindicators failed to allocate memory");
				}
				client->indicators[count] = xmalloc(value.length + 1);
				memcpy(client->indicators[count], value.value, value.length);
				client->indicators[count][value.length] = '\0';
				count++;
			}
		}
	}

done:
	/* slot [count] is zeroed by recallocarray, serves as NULL sentinel */

out:
	if (ctx->major != GSS_S_COMPLETE && client->indicators != NULL) {
		for (i = 0; i < count; i++)
			free(client->indicators[i]);
		free(client->indicators);
		client->indicators = NULL;
	}
	(void) gss_release_buffer(&ctx->minor, &value);
	(void) gss_release_buffer(&ctx->minor, &display_value);
	(void) gss_release_buffer_set(&ctx->minor, &attrs);
	return (ctx->major);
}

/* Extract the client details from a given context. This can only reliably
 * be called once for a context */

/* Privileged (called from accept_secure_ctx) */
OM_uint32
ssh_gssapi_getclient(Gssctxt *ctx, ssh_gssapi_client *client)
{
	int i = 0;
	int equal = 0;
	gss_name_t new_name = GSS_C_NO_NAME;
	gss_buffer_desc ename = GSS_C_EMPTY_BUFFER;

	if (options.gss_store_rekey && client->used && ctx->client_creds) {
		if (client->mech->oid.length != ctx->oid->length ||
		    (memcmp(client->mech->oid.elements,
		     ctx->oid->elements, ctx->oid->length) !=0)) {
			debug("Rekeyed credentials have different mechanism");
			return GSS_S_COMPLETE;
		}

		if ((ctx->major = gss_inquire_cred_by_mech(&ctx->minor,
		    ctx->client_creds, ctx->oid, &new_name,
		    NULL, NULL, NULL))) {
			ssh_gssapi_error(ctx);
			return (ctx->major);
		}

		ctx->major = gss_compare_name(&ctx->minor, client->name,
		    new_name, &equal);

		if (GSS_ERROR(ctx->major)) {
			ssh_gssapi_error(ctx);
			return (ctx->major);
		}

		if (!equal) {
			debug("Rekeyed credentials have different name");
			return GSS_S_COMPLETE;
		}

		debug("Marking rekeyed credentials for export");

		gss_release_name(&ctx->minor, &client->name);
		gss_release_cred(&ctx->minor, &client->creds);
		client->name = new_name;
		client->creds = ctx->client_creds;
		ctx->client_creds = GSS_C_NO_CREDENTIAL;
		client->updated = 1;
		return GSS_S_COMPLETE;
	}

	client->mech = NULL;

	while (supported_mechs[i]->name != NULL) {
		if (supported_mechs[i]->oid.length == ctx->oid->length &&
		    (memcmp(supported_mechs[i]->oid.elements,
		    ctx->oid->elements, ctx->oid->length) == 0))
			client->mech = supported_mechs[i];
		i++;
	}

	if (client->mech == NULL)
		return GSS_S_FAILURE;

	if (ctx->client_creds &&
	    (ctx->major = gss_inquire_cred_by_mech(&ctx->minor,
	     ctx->client_creds, ctx->oid, &client->name, NULL, NULL, NULL))) {
		ssh_gssapi_error(ctx);
		return (ctx->major);
	}

	if ((ctx->major = gss_display_name(&ctx->minor, ctx->client,
	    &client->displayname, NULL))) {
		ssh_gssapi_error(ctx);
		return (ctx->major);
	}

	if ((ctx->major = gss_export_name(&ctx->minor, ctx->client,
	    &ename))) {
		ssh_gssapi_error(ctx);
		return (ctx->major);
	}

	if ((ctx->major = ssh_gssapi_parse_ename(ctx,&ename,
	    &client->exportedname))) {
		return (ctx->major);
	}

	(void)gss_release_buffer(&ctx->minor, &ename);
	/* Retrieve authentication indicators, if they exist */
	if ((ctx->major = ssh_gssapi_getindicators(ctx,
	    ctx->client, client))) {
		ssh_gssapi_error(ctx);
		return (ctx->major);
	}

	/* We can't copy this structure, so we just move the pointer to it */
	client->creds = ctx->client_creds;
	ctx->client_creds = GSS_C_NO_CREDENTIAL;
	return (ctx->major);
}

/* Returns non-zero if Kerberos credentials have already been stored. */
int
ssh_gssapi_credentials_stored(void)
{
	return gssapi_client.store.envval != NULL;
}

/* Returns a pointer to the credential-cache descriptor for this session. */
ssh_gssapi_ccache *
ssh_gssapi_get_ccache(void)
{
	return &gssapi_client.store;
}

/* Log human-readable GSSAPI major and minor status strings. */
static void
log_gss_error(OM_uint32 major, OM_uint32 minor, const char *label)
{
	OM_uint32 lmin, mctx;
	gss_buffer_desc emsg = GSS_C_EMPTY_BUFFER;

	mctx = 0;
	do {
		gss_display_status(&lmin, major, GSS_C_GSS_CODE,
		    GSS_C_NO_OID, &mctx, &emsg);
		logit("%s: %.*s", label, (int)emsg.length, (char *)emsg.value);
		gss_release_buffer(&lmin, &emsg);
	} while (mctx != 0);

	mctx = 0;
	do {
		gss_display_status(&lmin, minor, GSS_C_MECH_CODE,
		    &gssapi_kerberos_mech.oid, &mctx, &emsg);
		if (emsg.length > 0)
			logit("%s: %.*s", label,
			    (int)emsg.length, (char *)emsg.value);
		gss_release_buffer(&lmin, &emsg);
	} while (mctx != 0);
}

/* Log the canonical string form of a GSSAPI name as a debug message. */
static void
debug_gss_name(const char *label, gss_name_t name)
{
	OM_uint32 lmin;
	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;

	if (gss_display_name(&lmin, name, &buf, NULL) == GSS_S_COMPLETE) {
		debug2_f("%s: %.*s", label, (int)buf.length, (char *)buf.value);
		gss_release_buffer(&lmin, &buf);
	} else {
		debug2_f("%s: (gss_display_name failed)", label);
	}
}

/*
 * Check whether the user already has valid GSSAPI initiator credentials
 * (e.g. a Kerberos TGT) in their default credential store with at least
 * min_lifetime seconds remaining.  Pass GSS_C_INDEFINITE to accept any
 * positive remaining lifetime.  Runs as the user.
 * Returns 1 if sufficient credentials exist, 0 otherwise.
 */
int
ssh_gssapi_user_has_valid_tgt(u_int min_lifetime)
{
	OM_uint32 major, minor, lifetime = 0;
	gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
	int found = 0;

	major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
	    GSS_C_NO_OID_SET, GSS_C_INITIATE, &cred, NULL, &lifetime);
	if (!GSS_ERROR(major) && lifetime > 0 &&
	    (min_lifetime == GSS_C_INDEFINITE || lifetime >= min_lifetime))
		found = 1;
	if (cred != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&minor, &cred);
	return found;
}


/*
 * Perform S4U2Self (protocol transition): acquire a Kerberos service ticket
 * for the SSH user on behalf of the host principal.  Runs privileged.
 * Populates gssapi_client.{creds,mech,displayname,exportedname} on success.
 * Returns 0 on success, -1 on failure.
 *
 * When ssh and authctxt are non-NULL and the build includes S4U X.509
 * attestation support, an attestation certificate is constructed from the
 * keytab-derived signing key and passed as GSS_KRB5_NT_X509_CERT.  For
 * cross-realm users (user realm != host realm) the plain username path
 * is used instead, as the KDC would not verify the cert in that case.
 */
/* Privileged */
int
ssh_gssapi_s4u2self(const char *user, u_int lifetime,
    struct ssh *ssh, Authctxt *authctxt)
{
	OM_uint32 major, minor, status;
	gss_OID_set oidset = GSS_C_NO_OID_SET;
	gss_name_t host_name = GSS_C_NO_NAME;
	gss_name_t user_name = GSS_C_NO_NAME;
	gss_cred_id_t host_creds = GSS_C_NO_CREDENTIAL;
	gss_cred_id_t impersonated_creds = GSS_C_NO_CREDENTIAL;
	gss_buffer_desc gssbuf, displayname = GSS_C_EMPTY_BUFFER;
	char lname[NI_MAXHOST];
	char *val;

	if (gethostname(lname, sizeof(lname)) != 0) {
		logit_f("gethostname: %s", strerror(errno));
		return -1;
	}

	/* Acquire acceptor credential for host/ from the keytab */
	gss_create_empty_oid_set(&status, &oidset);
	gss_add_oid_set_member(&status, &gssapi_kerberos_mech.oid, &oidset);

	xasprintf(&val, "host@%s", lname);
	gssbuf.value = val;
	gssbuf.length = strlen(val);
	major = gss_import_name(&minor, &gssbuf,
	    GSS_C_NT_HOSTBASED_SERVICE, &host_name);
	free(val);
	if (GSS_ERROR(major)) {
		logit_f("gss_import_name (host) failed");
		gss_release_oid_set(&status, &oidset);
		return -1;
	}
	debug_gss_name("host name parsed as", host_name);

	debug2_f("acquiring host credentials as uid=%u euid=%u, principal=host@%s",
	    (unsigned)getuid(), (unsigned)geteuid(), lname);
#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
	{
# if defined(KRB5)
		/*
		 * Resolve the keytab path: krb5_kt_default_name respects
		 * KRB5_KTNAME and krb5.conf default_keytab_name.
		 */
		char keytab_name[MAXPATHLEN];
		krb5_context tmp_ctx;

		keytab_name[0] = '\0';
		if (krb5_init_context(&tmp_ctx) == 0) {
			(void)krb5_kt_default_name(tmp_ctx, keytab_name,
			    sizeof(keytab_name));
			krb5_free_context(tmp_ctx);
		}
		if (keytab_name[0] == '\0')
			strlcpy(keytab_name, "FILE:/etc/krb5.keytab",
			    sizeof(keytab_name));
		/*
		 * client_keytab lets GSSAPI do AS-REQ to obtain a TGT for the
		 * host principal (initiator role needed for S4U2Self).
		 * keytab covers the acceptor role.
		 * ccache: MEMORY: keeps the resulting TGT volatile.
		 */
		gss_key_value_element_desc store_elements[] = {
			{ "client_keytab", keytab_name },
			{ "keytab", keytab_name },
			{ "ccache", "MEMORY:" },
		};
		const gss_key_value_set_desc cred_store = { 3, store_elements };
# else
		gss_key_value_element_desc store_elements[] = {
			{ "ccache", "MEMORY:" },
		};
		const gss_key_value_set_desc cred_store = { 1, store_elements };
# endif

		major = gss_acquire_cred_from(&minor, host_name, lifetime,
		    oidset, GSS_C_BOTH, &cred_store, &host_creds, NULL, NULL);
	}
#else
	major = gss_acquire_cred(&minor, host_name, lifetime,
	    oidset, GSS_C_BOTH, &host_creds, NULL, NULL);
#endif
	gss_release_name(&minor, &host_name);
	if (GSS_ERROR(major)) {
		logit_f("gss_acquire_cred(host@%s) failed as uid=%u euid=%u",
		    lname, (unsigned)getuid(), (unsigned)geteuid());
		log_gss_error(major, minor, "S4U2Self: gss_acquire_cred");
		gss_release_oid_set(&status, &oidset);
		return -1;
	}

	/*
	 * Import the user name for S4U2Self.
	 *
	 * When attestation support is compiled in, try to build an X.509
	 * certificate and import it via GSS_KRB5_NT_X509_CERT (MIT krb5 >=
	 * 1.19).  The cert encodes the SSH auth event details so the KDC
	 * plugin can verify the attestation and inject auth indicators.
	 *
	 * If attestation was attempted (keytab found, same realm, same host)
	 * but the cert build failed for any reason, S4U2Self is dropped
	 * entirely — we do NOT fall back to plain username S4U2Self.  The SSH
	 * connection has already been authenticated and succeeds regardless.
	 *
	 * S4U2Self with plain GSS_C_NT_USER_NAME is used only when attestation
	 * was never attempted:
	 *   - ssh or authctxt is NULL (called without full context)
	 *   - the user's realm differs from the host realm (cross-realm)
	 *   - GSS_KRB5_NT_X509_CERT is not declared in the installed krb5 headers
	 */
/*
 * HAVE_DECL_GSS_KRB5_NT_X509_CERT is set by AC_CHECK_DECL in configure.ac.
 * If the probe is absent or the installed krb5 headers are too old, this
 * macro evaluates to 0 and the entire attestation path is compiled out.
 */
#if defined(KRB5) && !defined(HEIMDAL) && defined(WITH_OPENSSL) && \
    HAVE_DECL_GSS_KRB5_NT_X509_CERT
	if (ssh != NULL && authctxt != NULL &&
	    ssh->kex != NULL && ssh->kex->session_id != NULL) {
		krb5_context kctx = NULL;
		unsigned char *ikm = NULL;
		size_t ikm_len = 0;
		krb5_enctype enctype = 0;
		uint32_t kvno = 0;
		unsigned char *cert_der = NULL;
		size_t cert_der_len = 0;
		const char *realm = NULL;
		char realm_buf[256];
		int same_realm = 0;
		int tried_x509 = 0;
		int fips_mode = EVP_default_properties_is_fips_enabled(NULL);

		realm_buf[0] = '\0';

		debug2_f("S4U X.509: entered attestation path for user %.100s "
		    "fips=%d", user, fips_mode);

		/*
		 * Resolve the host realm by looking up the host/ principal in
		 * the keytab and extracting the realm from there.  We use
		 * krb5_sname_to_principal() which respects krb5.conf mappings.
		 */
		if (krb5_init_context(&kctx) != 0) {
			debug2_f("S4U X.509: krb5_init_context failed; "
			    "falling back to plain S4U2Self");
		} else {
			krb5_principal host_princ = NULL;

			if (krb5_sname_to_principal(kctx, lname, "host",
			    KRB5_NT_SRV_HST, &host_princ) != 0) {
				debug2_f("S4U X.509: krb5_sname_to_principal "
				    "failed for host/%s", lname);
			} else {
				const krb5_data *r =
				    krb5_princ_realm(kctx, host_princ);
				if (r && r->data && r->length > 0 &&
				    r->length < sizeof(realm_buf)) {
					memcpy(realm_buf, r->data, r->length);
					realm_buf[r->length] = '\0';
					realm = realm_buf;
				}
				krb5_free_principal(kctx, host_princ);
			}

			if (realm == NULL || *realm == '\0') {
				debug2_f("S4U X.509: could not determine host "
				    "realm for %s; falling back to plain "
				    "S4U2Self", lname);
			} else {
				debug2_f("S4U X.509: attempting attestation "
				    "for user %.100s, host realm %.64s "
				    "fips=%d", user, realm, fips_mode);
				if (ssh_gssapi_s4u_x509_get_keytab_key(kctx,
				    lname, realm, fips_mode,
				    &ikm, &ikm_len, &enctype, &kvno) != 0)
					debug2_f("S4U X.509: keytab key "
					    "retrieval failed for host/%s@%s",
					    lname, realm);
			}
		}

		/*
		 * Determine whether the user's realm matches the host realm.
		 * If the username has no '@', assume it is a local name in the
		 * same realm.  Compare case-insensitively per Kerberos norms.
		 */
		{
			const char *at = strrchr(user, '@');
			if (at == NULL || realm == NULL || *realm == '\0') {
				same_realm = 1;
			} else {
				same_realm =
				    (strcasecmp(at + 1, realm) == 0);
			}
		}

		if (ikm != NULL && !same_realm) {
			debug2_f("S4U X.509: skipping attestation for "
			    "cross-realm user %.100s (host realm %.64s)",
			    user, realm ? realm : "(unknown)");
		}
		if (ikm != NULL && same_realm) {
			/*
			 * We have the keytab key and the user is in the host
			 * realm — attestation should be possible.  Any failure
			 * from here on drops S4U2Self entirely.
			 */
			tried_x509 = 1;

			/* Prefer non-Ed25519 host keys in FIPS mode */
			const struct sshkey *host_pubkey =
			    get_hostkey_public_by_type(KEY_RSA, 0, ssh);
			if (host_pubkey == NULL)
				host_pubkey = get_hostkey_public_by_type(
				    KEY_ECDSA, 0, ssh);
			if (host_pubkey == NULL && !fips_mode)
				host_pubkey = get_hostkey_public_by_type(
				    KEY_ED25519, 0, ssh);

			/* Extract auth method: first word of session_info */
			const char *auth_method = "unknown";
			char *method_buf = NULL;
			if (authctxt->session_info != NULL &&
			    sshbuf_len(authctxt->session_info) > 0) {
				const char *si = (const char *)sshbuf_ptr(
				    authctxt->session_info);
				size_t si_len =
				    sshbuf_len(authctxt->session_info);
				const char *sp = memchr(si, ' ', si_len);
				const char *nl = memchr(si, '\n', si_len);
				size_t mlen = sp ? (size_t)(sp - si)
				    : nl ? (size_t)(nl - si) : si_len;
				method_buf = xmalloc(mlen + 1);
				memcpy(method_buf, si, mlen);
				method_buf[mlen] = '\0';
				auth_method = method_buf;
			}

			/* Client address "ip:port" */
			char *client_addr = NULL;
			{
				const char *ip = ssh_remote_ipaddr(ssh);
				int port = ssh_remote_port(ssh);
				if (ip != NULL)
					xasprintf(&client_addr, "%s:%d",
					    ip, port);
			}

			if (host_pubkey == NULL)
				debug2_f("S4U X.509: no suitable host public "
				    "key found");

			if (host_pubkey != NULL &&
			    ssh_gssapi_s4u_x509_build_cert(
			        user, realm, auth_method,
			        ssh->kex->session_id,
			        authctxt->auth_method_key,
			        authctxt->auth_method_info,
			        client_addr,
			        host_pubkey,
			        ikm, ikm_len,
			        enctype, kvno,
			        lname, lifetime,
			        &cert_der, &cert_der_len) == 0) {
				gssbuf.value  = cert_der;
				gssbuf.length = cert_der_len;
				major = gss_import_name(&minor, &gssbuf,
				    GSS_KRB5_NT_X509_CERT, &user_name);
				free(cert_der);
				cert_der = NULL;
				if (!GSS_ERROR(major))
					debug_f("S4U X.509 cert imported for "
					    "user %.100s", user);
				else {
					logit_f("gss_import_name (X.509 cert)"
					    " failed");
					gss_release_name(&minor, &user_name);
					user_name = GSS_C_NO_NAME;
				}
			}
			free(method_buf);
			free(client_addr);
			/* cert_der is NULL here: freed and cleared above on
			 * success, or never set on build failure */
		}

		/*
		 * If attestation was attempted but failed (user_name not set),
		 * drop S4U2Self entirely.  SSH auth has already succeeded.
		 */
		if (tried_x509 && user_name == GSS_C_NO_NAME) {
			logit_f("S4U X.509: attestation failed for user %.100s;"
			    " S4U2Self skipped", user);
			freezero(ikm, ikm_len);
			if (kctx != NULL)
				krb5_free_context(kctx);
			gss_release_cred(&minor, &host_creds);
			gss_release_oid_set(&status, &oidset);
			return 0;
		}

		freezero(ikm, ikm_len);
		if (kctx != NULL)
			krb5_free_context(kctx);
	}
#else /* !(KRB5 && !HEIMDAL && WITH_OPENSSL && HAVE_DECL_GSS_KRB5_NT_X509_CERT) */
	debug2_f("S4U X.509 attestation not compiled in "
	    "(missing KRB5, OPENSSL, or GSS_KRB5_NT_X509_CERT); "
	    "using plain S4U2Self");
#endif /* KRB5 && !HEIMDAL && WITH_OPENSSL && HAVE_DECL_GSS_KRB5_NT_X509_CERT */

	/* Plain username fallback (cross-realm, no keytab, or attestation not compiled in) */
	if (user_name == GSS_C_NO_NAME) {
		gssbuf.value = (void *)user;
		gssbuf.length = strlen(user);
		major = gss_import_name(&minor, &gssbuf,
		    GSS_C_NT_USER_NAME, &user_name);
		if (GSS_ERROR(major)) {
			logit_f("gss_import_name (user) failed");
			gss_release_cred(&minor, &host_creds);
			gss_release_oid_set(&status, &oidset);
			return -1;
		}
	}
	debug_gss_name("user name parsed as", user_name);

	/* S4U2Self: obtain a service ticket for the user without their creds */
	debug2_f("calling gss_acquire_cred_impersonate_name for user %.100s", user);
	major = gss_acquire_cred_impersonate_name(&minor,
	    host_creds, user_name, lifetime,
	    oidset, GSS_C_INITIATE,
	    &impersonated_creds, NULL, NULL);

	gss_release_cred(&minor, &host_creds);
	gss_release_oid_set(&status, &oidset);
	if (GSS_ERROR(major)) {
		logit_f("gss_acquire_cred_impersonate_name failed for %.100s",
		    user);
		log_gss_error(major, minor,
		    "S4U2Self: gss_acquire_cred_impersonate_name");
		gss_release_name(&minor, &user_name);
		return -1;
	}

	/*
	 * Obtain the principal name from the issued credential rather than
	 * from the name we passed in.  This works regardless of whether the
	 * user was identified by username or by X.509 cert, and gives the
	 * KDC-canonicalised principal (e.g. user@REALM) as stored in the
	 * ticket — the form that krb5_parse_name and the ccache expect.
	 */
	gss_release_name(&minor, &user_name);
	user_name = GSS_C_NO_NAME;
	major = gss_inquire_cred(&minor, impersonated_creds,
	    &user_name, NULL, NULL, NULL);
	if (GSS_ERROR(major)) {
		logit_f("gss_inquire_cred failed after S4U2Self");
		gss_release_cred(&minor, &impersonated_creds);
		return -1;
	}

	/* Get the display name (Kerberos principal string) for storecreds */
	major = gss_display_name(&minor, user_name, &displayname, NULL);
	gss_release_name(&minor, &user_name);
	if (GSS_ERROR(major)) {
		logit_f("gss_display_name failed");
		gss_release_cred(&minor, &impersonated_creds);
		return -1;
	}

	/* Populate gssapi_client for storecreds_s4u2self and s4u2proxy */
	gssapi_client.mech = &gssapi_kerberos_mech;
	gssapi_client.creds = impersonated_creds;
	gssapi_client.displayname.value = xmalloc(displayname.length + 1);
	memcpy(gssapi_client.displayname.value,
	    displayname.value, displayname.length);
	((char *)gssapi_client.displayname.value)[displayname.length] = '\0';
	gssapi_client.displayname.length = displayname.length;
	/*
	 * exportedname is used by ssh_gssapi_krb5_storecreds → krb5_parse_name.
	 * gss_display_name for a user-name returns the canonical principal
	 * string (e.g. user@REALM) which krb5_parse_name can consume directly.
	 */
	gssapi_client.exportedname.value = xmalloc(displayname.length + 1);
	memcpy(gssapi_client.exportedname.value,
	    displayname.value, displayname.length);
	((char *)gssapi_client.exportedname.value)[displayname.length] = '\0';
	gssapi_client.exportedname.length = displayname.length;

	gss_release_buffer(&minor, &displayname);
	debug2_f("S4U2Self succeeded for %.100s", user);
	return 0;
}

/* As user — write the S4U2Self ticket into a new ccache via mech->storecreds */
void
ssh_gssapi_storecreds_s4u2self(void)
{
	if (gssapi_client.mech == NULL || gssapi_client.mech->storecreds == NULL) {
		debug2_f("no GSSAPI mechanism for storing S4U2Self credentials");
		return;
	}
	(*gssapi_client.mech->storecreds)(&gssapi_client);
}

/*
 * Perform S4U2Proxy for each configured service principal, then flush all
 * resulting tickets into the user's ccache.  Runs as user, after
 * ssh_gssapi_storecreds_s4u2self() has created the ccache.
 *
 * gssapi_client.creds (the S4U2Self proxy credential) is passed as the
 * initiator to gss_init_sec_context(); the GSSAPI library presents the TGT
 * and evidence ticket to the KDC via S4U2Proxy TGS-REQ.  The output token
 * (AP-REQ) is discarded — we do not connect to the target service.
 *
 * After iterating all services, gss_store_cred() flushes the accumulated
 * proxy service tickets from the credential's internal ccache into the
 * KRB5CCNAME ccache that storecreds_s4u2self() already created.
 */
/* As user */
void
ssh_gssapi_s4u2proxy(char **services, u_int nservices, u_int lifetime)
{
	OM_uint32 major, minor;
	gss_buffer_desc service_buf, output_token = GSS_C_EMPTY_BUFFER;
	gss_name_t target_name;
	gss_ctx_id_t ctx;
	u_int i;

	if (gssapi_client.creds == GSS_C_NO_CREDENTIAL) {
		debug2_f("no proxy credential available");
		return;
	}
	if (gssapi_client.store.envval == NULL) {
		debug2_f("no ccache path set; cannot store proxy tickets");
		return;
	}

	debug2_f("starting S4U2Proxy as uid=%u euid=%u, %u service(s), ccache=%s",
	    (unsigned)getuid(), (unsigned)geteuid(), nservices,
	    gssapi_client.store.envval);

	/* Point the GSSAPI library at the user's ccache for ticket storage */
	setenv("KRB5CCNAME", gssapi_client.store.envval, 1);

	for (i = 0; i < nservices; i++) {
		ctx = GSS_C_NO_CONTEXT;
		target_name = GSS_C_NO_NAME;

		service_buf.value = services[i];
		service_buf.length = strlen(services[i]);

		/*
		 * GSS_C_NO_OID: let the library determine the name type.
		 * With Kerberos as the active mechanism, a fully-qualified
		 * principal like "svc/host@REALM" is parsed correctly.
		 */
		major = gss_import_name(&minor, &service_buf,
		    GSS_C_NO_OID, &target_name);
		if (GSS_ERROR(major)) {
			logit_f("gss_import_name failed for %.200s",
			    services[i]);
			log_gss_error(major, minor, "S4U2Proxy: gss_import_name");
			continue;
		}
		debug_gss_name("target service name parsed as", target_name);

		debug2_f("calling gss_init_sec_context for %.200s", services[i]);
		major = gss_init_sec_context(&minor,
		    gssapi_client.creds,		/* proxy credential */
		    &ctx, target_name,
		    GSS_C_NO_OID,			/* default mech (Kerberos) */
		    0,					/* no flags, no mutual auth */
		    lifetime,
		    GSS_C_NO_CHANNEL_BINDINGS,
		    GSS_C_NO_BUFFER,			/* no input token */
		    NULL,				/* actual_mech_type */
		    &output_token,
		    NULL,				/* ret_flags */
		    NULL);				/* time_rec */

		gss_release_buffer(&minor, &output_token);
		gss_release_name(&minor, &target_name);
		if (ctx != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);

		if (GSS_ERROR(major)) {
			logit_f("S4U2Proxy for %.200s on behalf of %.200s failed",
			    services[i],
			    (char *)gssapi_client.displayname.value);
			log_gss_error(major, minor,
			    "S4U2Proxy: gss_init_sec_context");
		} else
			debug2_f("S4U2Proxy ticket obtained for %.200s",
			    services[i]);
	}

	/*
	 * Flush all proxy service tickets from the credential's internal
	 * ccache into the KRB5CCNAME ccache via gss_store_cred().
	 */
	major = gss_store_cred(&minor, gssapi_client.creds, GSS_C_INITIATE,
	    GSS_C_NO_OID, 1 /* overwrite_cred */, 1 /* default_cred */,
	    NULL, NULL);
	if (GSS_ERROR(major)) {
		logit_f("gss_store_cred failed; proxy tickets may be missing");
		log_gss_error(major, minor, "S4U2Proxy: gss_store_cred");
	}

	unsetenv("KRB5CCNAME");
}

#ifndef KRB5
/* As user - called on fatal/exit; full implementation in gss-serv-krb5.c */
void
ssh_gssapi_cleanup_creds(void)
{
}

/*
 * Filter the user's ccache; full implementation in gss-serv-krb5.c.
 */
void
ssh_gssapi_krb5_filter_ccache(u_int drop_flags,
    char **proxy_services, u_int nproxy_services)
{
}
#endif /* !KRB5 */

/* As user */
int
ssh_gssapi_storecreds(void)
{
	if (options.gss_deleg_creds == 0) {
		debug2_f("delegate credential is disabled, doing nothing");
		return 0;
	}

	if (gssapi_client.mech && gssapi_client.mech->storecreds) {
		return (*gssapi_client.mech->storecreds)(&gssapi_client);
	} else
		debug("ssh_gssapi_storecreds: Not a GSSAPI mechanism");

	return 0;
}

/* This allows GSSAPI methods to do things to the child's environment based
 * on the passed authentication process and credentials.
 */
/* As user */
void
ssh_gssapi_do_child(char ***envp, u_int *envsizep)
{

	if (gssapi_client.store.envvar != NULL &&
	    gssapi_client.store.envval != NULL) {
		debug("Setting %s to %s", gssapi_client.store.envvar,
		    gssapi_client.store.envval);
		child_set_env(envp, envsizep, gssapi_client.store.envvar,
		    gssapi_client.store.envval);
	}
}

/* Privileged */
int
ssh_gssapi_userok(char *user, struct passwd *pw, int kex)
{
	OM_uint32 lmin;
	size_t i;

	(void) kex; /* used in privilege separation */

	if (gssapi_client.exportedname.length == 0 ||
	    gssapi_client.exportedname.value == NULL) {
		debug("No suitable client data");
		return 0;
	}
	if (gssapi_client.mech && gssapi_client.mech->userok)
		if ((*gssapi_client.mech->userok)(&gssapi_client, user)) {
			gssapi_client.used = 1;
			gssapi_client.store.owner = pw;
			return 1;
		} else {
			/* Destroy delegated credentials if userok fails */
			gss_release_buffer(&lmin, &gssapi_client.displayname);
			gss_release_buffer(&lmin, &gssapi_client.exportedname);
			gss_release_cred(&lmin, &gssapi_client.creds);

			if (gssapi_client.indicators != NULL) {
				for (i = 0; gssapi_client.indicators[i] != NULL; i++)
					free(gssapi_client.indicators[i]);
				free(gssapi_client.indicators);
			}

			explicit_bzero(&gssapi_client, sizeof(ssh_gssapi_client));
			return 0;
		}
	else
		debug("ssh_gssapi_userok: Unknown GSSAPI mechanism");
	return (0);
}

/* These bits are only used for rekeying. The unpriviledged child is running
 * as the user, the monitor is root.
 *
 * In the child, we want to :
 *    *) Ask the monitor to store our credentials into the store we specify
 *    *) If it succeeds, maybe do a PAM update
 */

/* Stuff for PAM */

#ifdef USE_PAM
static int ssh_gssapi_simple_conv(int n, const struct pam_message **msg,
    struct pam_response **resp, void *data)
{
	return (PAM_CONV_ERR);
}
#endif

void
ssh_gssapi_rekey_creds(void) {
	int ok;
#ifdef USE_PAM
	int ret;
	pam_handle_t *pamh = NULL;
	struct pam_conv pamconv = {ssh_gssapi_simple_conv, NULL};
	char *envstr;
#endif

	if (gssapi_client.store.envval == NULL)
		return;

	ok = mm_ssh_gssapi_update_creds(&gssapi_client.store);

	if (!ok)
		return;

	debug("Rekeyed credentials stored successfully");

	/* Actually managing to play with the ssh pam stack from here will
	 * be next to impossible. In any case, we may want different options
	 * for rekeying. So, use our own :)
	 */
#ifdef USE_PAM	
	ret = pam_start("sshd-rekey", gssapi_client.store.owner->pw_name,
 	    &pamconv, &pamh);
	if (ret)
		return;

	xasprintf(&envstr, "%s=%s", gssapi_client.store.envvar,
	    gssapi_client.store.envval);

	ret = pam_putenv(pamh, envstr);
	free(envstr);
	if (!ret)
		pam_setcred(pamh, PAM_REINITIALIZE_CRED);
	pam_end(pamh, PAM_SUCCESS);
#endif
}

int
ssh_gssapi_update_creds(ssh_gssapi_ccache *store) {
	int ok = 0;

	/* Check we've got credentials to store */
	if (!gssapi_client.updated)
		return 0;

	gssapi_client.updated = 0;

	temporarily_use_uid(gssapi_client.store.owner);
	if (gssapi_client.mech && gssapi_client.mech->updatecreds)
		ok = (*gssapi_client.mech->updatecreds)(store, &gssapi_client);
	else
		debug("No update function for this mechanism");

	restore_uid();

	return ok;
}

/* Privileged */
const char *ssh_gssapi_displayname(void)
{
	if (gssapi_client.displayname.length == 0 ||
	    gssapi_client.displayname.value == NULL)
		return NULL;
	return (char *)gssapi_client.displayname.value;
}

#endif
