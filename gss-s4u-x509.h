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

#ifndef _GSS_S4U_X509_H
#define _GSS_S4U_X509_H

#if defined(GSSAPI) && defined(KRB5) && !defined(HEIMDAL) && defined(WITH_OPENSSL)

#include <stdint.h>
#include <sys/types.h>

#include <krb5.h>

struct sshbuf;
struct sshkey;

/*
 * Read the host keytab and locate the best entry for host/hostname@REALM.
 * Enctype preference order: 20 > 19 > 18 > 17; others are rejected.
 * In FIPS mode, enctypes 17 and 19 (AES-128) are also rejected.
 *
 * On success returns 0 and sets:
 *   *ikm_out      — malloc'd copy of the raw key bytes (caller must free)
 *   *ikm_len_out  — length of *ikm_out
 *   *enctype_out  — enctype of the selected entry
 *   *kvno_out     — key version number of the selected entry
 */
int	 ssh_gssapi_s4u_x509_get_keytab_key(krb5_context ctx,
	    const char *hostname, const char *realm, int fips_mode,
	    unsigned char **ikm_out, size_t *ikm_len_out,
	    krb5_enctype *enctype_out, uint32_t *kvno_out);

/*
 * Build a DER-encoded SSH S4U2Self attestation X.509 certificate.
 *
 * Parameters:
 *   user            SSH username (cert Subject CN)
 *   realm           Kerberos realm of the user (and host)
 *   auth_method     "publickey", "password", or "keyboard-interactive"
 *   session_id_buf  SSH session ID bytes (from ssh->kex->session_id)
 *   auth_method_key user's public key (pubkey auth) or NULL
 *   key_fingerprint "SHA256:…" fingerprint string or NULL
 *   client_address  "ip:port" string or NULL
 *   host_pubkey     SSH host public key (for SPKI in binding extension)
 *   ikm / ikm_len   keytab key bytes (from ssh_gssapi_s4u_x509_get_keytab_key)
 *   enctype         Kerberos enctype of the keytab entry
 *   kvno            key version number of the keytab entry
 *   hostname        server hostname component (e.g. "host.example.com")
 *   cert_lifetime   validity window in seconds
 *   cert_der_out    OUT: malloc'd DER bytes (caller must free on success)
 *   cert_der_len_out OUT: length of *cert_der_out
 *
 * Returns 0 on success, -1 on failure.
 */
int	 ssh_gssapi_s4u_x509_build_cert(
	    const char *user, const char *realm,
	    const char *auth_method,
	    const struct sshbuf *session_id_buf,
	    const struct sshkey *auth_method_key,
	    const char *key_fingerprint,
	    const char *client_address,
	    const struct sshkey *host_pubkey,
	    const unsigned char *ikm, size_t ikm_len,
	    krb5_enctype enctype, uint32_t kvno,
	    const char *hostname,
	    u_int cert_lifetime,
	    unsigned char **cert_der_out, size_t *cert_der_len_out);

#endif /* GSSAPI && KRB5 && !HEIMDAL && WITH_OPENSSL */

#endif /* _GSS_S4U_X509_H */
