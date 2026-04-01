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
 * Private declarations shared among gss-s4u-x509-*.c files.
 * Not for inclusion outside this subsystem.
 */

#ifndef GSS_S4U_X509_INTERNAL_H
#define GSS_S4U_X509_INTERNAL_H

#if defined(GSSAPI) && defined(KRB5) && !defined(HEIMDAL) && defined(WITH_OPENSSL)

#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/* OIDs for custom X.509 extensions (under the IPA Kerberos cert sub-arc) */
#define OID_KERBEROS_SERVICE_ISSUER_BINDING "2.16.840.1.113730.3.8.15.3.1"
#define OID_SSH_AUTHN_CONTEXT               "2.16.840.1.113730.3.8.15.3.2"

/* OID for PKINIT SubjectAlternativeName (id-pkinit-san) */
#define OID_PKINIT_SAN           "1.3.6.1.5.2.2"

/* OID for id-pkinit-KPClientAuth extended key usage */
#define OID_PKINIT_KP_CLIENTAUTH "1.3.6.1.5.2.3.4"

/* Maximum lifetime for attestation certificates (seconds) */
#define SSH_S4U_CERT_LIFETIME_MAX 300u

/*
 * id-ce-kerberosServiceIssuerBinding:
 *   SEQUENCE {
 *     version     INTEGER (0),
 *     serviceType UTF8String,        -- "ssh", "oidc", "radius", "pam", ...
 *     principal   UTF8String,
 *     enctype     INTEGER,
 *     kvno        INTEGER,
 *     sigAlg      AlgorithmIdentifier,
 *     serviceKey  SubjectPublicKeyInfo,
 *     binding     OCTET STRING
 *   }
 */
typedef struct kerberos_service_issuer_binding_st {
	ASN1_INTEGER      *version;
	ASN1_UTF8STRING   *service_type;   /* "ssh", "oidc", "radius", "pam", ... */
	ASN1_UTF8STRING   *principal;
	ASN1_INTEGER      *enctype;
	ASN1_INTEGER      *kvno;
	X509_ALGOR        *sig_alg;
	X509_PUBKEY       *service_key;
	ASN1_OCTET_STRING *binding;
} KERBEROS_SERVICE_ISSUER_BINDING;

DECLARE_ASN1_FUNCTIONS(KERBEROS_SERVICE_ISSUER_BINDING)

/*
 * id-ce-sshAuthnContext:
 *   SEQUENCE {
 *     version         INTEGER (0),
 *     authMethod      UTF8String,
 *     sessionId       OCTET STRING,
 *     keyFingerprint  [0] EXPLICIT UTF8String OPTIONAL,
 *     clientAddress   [1] EXPLICIT UTF8String OPTIONAL
 *   }
 */
typedef struct ssh_authn_context_st {
	ASN1_INTEGER      *version;
	ASN1_UTF8STRING   *auth_method;
	ASN1_OCTET_STRING *session_id;
	ASN1_UTF8STRING   *key_fingerprint;  /* [0] EXPLICIT OPTIONAL */
	ASN1_UTF8STRING   *client_address;   /* [1] EXPLICIT OPTIONAL */
} SSH_AUTHN_CONTEXT;

DECLARE_ASN1_FUNCTIONS(SSH_AUTHN_CONTEXT)

/* gss-s4u-x509-crypto.c */
EVP_PKEY	*derive_attestation_key(const unsigned char *ikm, size_t ikm_len,
		    const char *hostname, const char *realm,
		    uint32_t kvno, int fips_mode, const char *hkdf_salt);
EVP_PKEY	*generate_ephemeral_key(int fips_mode);

/* gss-s4u-x509-asn1.c */
struct sshkey;
X509_PUBKEY	*sshkey_to_x509_pubkey(const struct sshkey *key);
int		 compute_binding_digest(X509_PUBKEY *spki,
		    const char *principal, uint32_t kvno,
		    const char *binding_label,
		    unsigned char digest[SHA256_DIGEST_LENGTH]);
int		 add_raw_extension(X509 *cert, const char *oid_str,
		    int critical, const unsigned char *der, int der_len);
int		 add_pkinit_san(X509 *cert, const char *username,
		    const char *realm);

#endif /* GSSAPI && KRB5 && !HEIMDAL && WITH_OPENSSL */

#endif /* GSS_S4U_X509_INTERNAL_H */
