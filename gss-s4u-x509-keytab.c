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
 * Kerberos keytab access for SSH S4U2Self attestation.
 * Enumerates the host keytab to find the best key entry for the
 * host/hostname@REALM principal, respecting FIPS enctype restrictions.
 */

#include "includes.h"

#if defined(GSSAPI) && defined(KRB5) && !defined(HEIMDAL) && defined(WITH_OPENSSL)

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <krb5.h>

#include "xmalloc.h"
#include "log.h"

#include "gss-s4u-x509.h"

/*
 * Preference order for keytab enctype (higher = more preferred).
 * Enctypes below 17 (DES/RC4) and unknown ones return 0 (reject).
 */
static int
enctype_preference(krb5_enctype e)
{
	switch (e) {
	case 20: return 4;	/* AES256-CTS-HMAC-SHA384-192 (RFC 8009) */
	case 19: return 3;	/* AES128-CTS-HMAC-SHA256-128 (RFC 8009) */
	case 18: return 2;	/* AES256-CTS-HMAC-SHA1-96    (RFC 3962) */
	case 17: return 1;	/* AES128-CTS-HMAC-SHA1-96    (RFC 3962) */
	default: return 0;
	}
}

/* ------------------------------------------------------------------ *
 * Open the host keytab and pick the best entry for host/hostname@REALM.
 *
 * Fills in *ikm_out (caller must free()), *enctype_out, *kvno_out.
 * Returns 0 on success.
 * ------------------------------------------------------------------ */
int
ssh_gssapi_s4u_x509_get_keytab_key(
    krb5_context ctx,
    const char *hostname, const char *realm,
    int fips_mode,
    unsigned char **ikm_out, size_t *ikm_len_out,
    krb5_enctype *enctype_out, uint32_t *kvno_out)
{
	krb5_keytab		 kt        = NULL;
	krb5_kt_cursor		 cursor;
	krb5_keytab_entry	 entry, best;
	krb5_principal		 host_princ = NULL;
	char			*princ_str  = NULL;
	int			 best_pref  = -1;
	int			 have_best  = 0;
	int			 ret        = -1;

	*ikm_out     = NULL;
	*ikm_len_out = 0;

	xasprintf(&princ_str, "host/%s@%s", hostname, realm);
	if (krb5_parse_name(ctx, princ_str, &host_princ) != 0) {
		debug2_f("S4U X.509: cannot parse host principal %s", princ_str);
		free(princ_str);
		return -1;
	}
	free(princ_str);

	if (krb5_kt_default(ctx, &kt) != 0) {
		debug2_f("S4U X.509: cannot open default keytab");
		krb5_free_principal(ctx, host_princ);
		return -1;
	}

	if (krb5_kt_start_seq_get(ctx, kt, &cursor) != 0)
		goto done;

	memset(&best, 0, sizeof(best));

	while (krb5_kt_next_entry(ctx, kt, &entry, &cursor) == 0) {
		if (!krb5_principal_compare(ctx, entry.principal, host_princ)) {
			krb5_free_keytab_entry_contents(ctx, &entry);
			continue;
		}
		int pref = enctype_preference(entry.key.enctype);
		if (pref == 0) {
			krb5_free_keytab_entry_contents(ctx, &entry);
			continue;
		}
		if (fips_mode && (entry.key.enctype == 17 ||
		    entry.key.enctype == 19)) {
			debug2_f("S4U X.509: skipping enctype %d (AES-128 "
			    "rejected in FIPS mode)", entry.key.enctype);
			krb5_free_keytab_entry_contents(ctx, &entry);
			continue;
		}
		if (pref > best_pref) {
			if (have_best)
				krb5_free_keytab_entry_contents(ctx, &best);
			best      = entry;
			best_pref = pref;
			have_best = 1;
		} else {
			krb5_free_keytab_entry_contents(ctx, &entry);
		}
	}
	krb5_kt_end_seq_get(ctx, kt, &cursor);

	if (!have_best) {
		debug2_f("S4U X.509: no suitable keytab entry found");
		goto done;
	}

	if (best.key.length == 0) {
		debug2_f("S4U X.509: keytab entry has zero-length key material");
		krb5_free_keytab_entry_contents(ctx, &best);
		goto done;
	}
	*ikm_len_out = (size_t)best.key.length;
	*ikm_out = malloc(*ikm_len_out);
	if (!*ikm_out) {
		krb5_free_keytab_entry_contents(ctx, &best);
		goto done;
	}
	memcpy(*ikm_out, best.key.contents, *ikm_len_out);
	*enctype_out = best.key.enctype;
	*kvno_out    = (uint32_t)best.vno;
	krb5_free_keytab_entry_contents(ctx, &best);
	debug2_f("S4U X.509: selected keytab entry enctype=%d kvno=%u "
	    "keylen=%zu for host/%s@%s",
	    (int)*enctype_out, *kvno_out, *ikm_len_out, hostname, realm);
	ret = 0;

done:
	krb5_kt_close(ctx, kt);
	krb5_free_principal(ctx, host_princ);
	return ret;
}

#endif /* GSSAPI && KRB5 && !HEIMDAL && WITH_OPENSSL */
