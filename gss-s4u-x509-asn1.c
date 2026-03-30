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
 * ASN.1 type definitions and X.509 helpers for S4U2Self attestation:
 *   - KERBEROS_SERVICE_ISSUER_BINDING and SSH_AUTHN_CONTEXT ASN.1 types (IMPLEMENT)
 *   - KRB5PrincipalName encoding for PKINIT subjectAltName
 *   - SSH host key → SubjectPublicKeyInfo conversion
 *   - Binding digest computation
 *   - Raw extension and PKINIT SAN insertion
 */

#include "includes.h"

#if defined(GSSAPI) && defined(KRB5) && !defined(HEIMDAL) && defined(WITH_OPENSSL)

#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#include "sshbuf.h"
#include "sshkey.h"
#include "crypto_api.h"
#include "log.h"

#include "gss-s4u-x509-internal.h"

/* ------------------------------------------------------------------ *
 * ASN.1 type implementations.
 *
 * These must match ipa_kdb_s4u_x509.c on the KDC side exactly.
 * Struct definitions live in gss-s4u-x509-internal.h.
 * ------------------------------------------------------------------ */

ASN1_SEQUENCE(KERBEROS_SERVICE_ISSUER_BINDING) = {
	ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, version,      ASN1_INTEGER),
	ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, service_type, ASN1_UTF8STRING),
	ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, principal,    ASN1_UTF8STRING),
	ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, enctype,      ASN1_INTEGER),
	ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, kvno,         ASN1_INTEGER),
	ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, sig_alg,      X509_ALGOR),
	ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, service_key,  X509_PUBKEY),
	ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, binding,      ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(KERBEROS_SERVICE_ISSUER_BINDING)

IMPLEMENT_ASN1_FUNCTIONS(KERBEROS_SERVICE_ISSUER_BINDING)

ASN1_SEQUENCE(SSH_AUTHN_CONTEXT) = {
	ASN1_SIMPLE(SSH_AUTHN_CONTEXT, version,          ASN1_INTEGER),
	ASN1_SIMPLE(SSH_AUTHN_CONTEXT, auth_method,      ASN1_UTF8STRING),
	ASN1_SIMPLE(SSH_AUTHN_CONTEXT, session_id,       ASN1_OCTET_STRING),
	ASN1_EXP_OPT(SSH_AUTHN_CONTEXT, key_fingerprint, ASN1_UTF8STRING, 0),
	ASN1_EXP_OPT(SSH_AUTHN_CONTEXT, client_address,  ASN1_UTF8STRING, 1),
} ASN1_SEQUENCE_END(SSH_AUTHN_CONTEXT)

IMPLEMENT_ASN1_FUNCTIONS(SSH_AUTHN_CONTEXT)

/*
 * KRB5PrincipalName (RFC 4556 / RFC 4120) for PKINIT subjectAltName:
 *   KRB5PrincipalName ::= SEQUENCE {
 *     realm         [0] EXPLICIT GeneralString,
 *     principalName [1] EXPLICIT PrincipalName
 *   }
 *   PrincipalName ::= SEQUENCE {
 *     name-type   [0] EXPLICIT INTEGER,
 *     name-string [1] EXPLICIT SEQUENCE OF GeneralString
 *   }
 *
 * These types are internal to add_pkinit_san; not exposed in the header.
 */

typedef STACK_OF(ASN1_GENERALSTRING) KRB5_KERBEROS_STRINGS;

ASN1_ITEM_TEMPLATE(KRB5_KERBEROS_STRINGS) =
	ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
	    KRB5_KERBEROS_STRINGS, ASN1_GENERALSTRING)
ASN1_ITEM_TEMPLATE_END(KRB5_KERBEROS_STRINGS)

IMPLEMENT_ASN1_ALLOC_FUNCTIONS(KRB5_KERBEROS_STRINGS)

typedef struct krb5_princ_name_st {
	ASN1_INTEGER          *name_type;    /* [0] EXPLICIT INTEGER */
	KRB5_KERBEROS_STRINGS *name_string; /* [1] EXPLICIT SEQUENCE OF */
} KRB5_PRINC_NAME;

DECLARE_ASN1_FUNCTIONS(KRB5_PRINC_NAME)

ASN1_SEQUENCE(KRB5_PRINC_NAME) = {
	ASN1_EXP(KRB5_PRINC_NAME, name_type,   ASN1_INTEGER,          0),
	ASN1_EXP(KRB5_PRINC_NAME, name_string, KRB5_KERBEROS_STRINGS, 1),
} ASN1_SEQUENCE_END(KRB5_PRINC_NAME)

IMPLEMENT_ASN1_FUNCTIONS(KRB5_PRINC_NAME)

typedef struct krb5_principal_name_st {
	ASN1_GENERALSTRING *realm;          /* [0] EXPLICIT GeneralString */
	KRB5_PRINC_NAME    *principal_name; /* [1] EXPLICIT SEQUENCE */
} KRB5_PRINCIPAL_NAME;

DECLARE_ASN1_FUNCTIONS(KRB5_PRINCIPAL_NAME)

ASN1_SEQUENCE(KRB5_PRINCIPAL_NAME) = {
	ASN1_EXP(KRB5_PRINCIPAL_NAME, realm,          ASN1_GENERALSTRING, 0),
	ASN1_EXP(KRB5_PRINCIPAL_NAME, principal_name, KRB5_PRINC_NAME,    1),
} ASN1_SEQUENCE_END(KRB5_PRINCIPAL_NAME)

IMPLEMENT_ASN1_FUNCTIONS(KRB5_PRINCIPAL_NAME)

/* ------------------------------------------------------------------ *
 * Convert an SSH host public key to X509_PUBKEY (SubjectPublicKeyInfo).
 * Returns a newly allocated X509_PUBKEY; caller must X509_PUBKEY_free().
 * ------------------------------------------------------------------ */
X509_PUBKEY *
sshkey_to_x509_pubkey(const struct sshkey *key)
{
	EVP_PKEY	*pkey = NULL;
	X509_PUBKEY	*spki = NULL;

	switch (key->type) {
	case KEY_RSA:
	case KEY_ECDSA:
		/* Take a reference so ownership is uniform below */
		pkey = key->pkey;
		if (!EVP_PKEY_up_ref(pkey))
			return NULL;
		break;
	case KEY_ED25519:
		if (!key->ed25519_pk)
			return NULL;
		pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
		    key->ed25519_pk, ED25519_PK_SZ);
		break;
	default:
		return NULL;
	}
	if (!pkey)
		return NULL;

	if (X509_PUBKEY_set(&spki, pkey) != 1) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
	EVP_PKEY_free(pkey);
	return spki;
}

/* ------------------------------------------------------------------ *
 * Compute binding digest:
 *   SHA256(serviceKey_SPKI_DER || BINDING_LABEL || principal || kvno_be32)
 *
 * Collision-resistance note: the concatenation lacks explicit length
 * prefixes on variable-length fields, but collision is not achievable
 * with current fields because:
 *   - spki_der is DER (self-delimiting, starts with 30 82 / 30 81)
 *   - BINDING_LABEL is a fixed-length constant string
 *   - principal has the form "host/name@REALM" (always contains '/')
 *   - kvno_be32 is a fixed 4-byte suffix
 * If new variable-length fields are added, length framing must be added.
 * ------------------------------------------------------------------ */
int
compute_binding_digest(X509_PUBKEY *spki, const char *principal,
    uint32_t kvno, const char *binding_label,
    unsigned char digest[SHA256_DIGEST_LENGTH])
{
	unsigned char	*spki_der = NULL;
	int		 spki_len;
	uint32_t	 kvno_be  = htonl(kvno);
	struct sshbuf	*b        = NULL;
	size_t		 dlen     = SHA256_DIGEST_LENGTH;
	int		 ret      = -1;

	spki_len = i2d_X509_PUBKEY(spki, &spki_der);
	if (spki_len <= 0)
		return -1;

	b = sshbuf_new();
	if (b == NULL ||
	    sshbuf_put(b, spki_der,      (size_t)spki_len)           != 0 ||
	    sshbuf_put(b, binding_label, strlen(binding_label))      != 0 ||
	    sshbuf_put(b, principal,     strlen(principal))          != 0 ||
	    sshbuf_put(b, &kvno_be,      sizeof(kvno_be))             != 0 ||
	    EVP_Q_digest(NULL, "SHA256", NULL,
	        sshbuf_ptr(b), sshbuf_len(b), digest, &dlen) != 1)
		goto done;
	ret = 0;
done:
	sshbuf_free(b);
	OPENSSL_free(spki_der);
	return ret;
}

/* ------------------------------------------------------------------ *
 * Add a custom extension with a raw DER-encoded value.
 * ------------------------------------------------------------------ */
int
add_raw_extension(X509 *cert, const char *oid_str, int critical,
    const unsigned char *der, int der_len)
{
	ASN1_OBJECT       *obj = OBJ_txt2obj(oid_str, 1);
	ASN1_OCTET_STRING *val = ASN1_OCTET_STRING_new();
	X509_EXTENSION    *ext = NULL;
	int                ret = -1;

	if (!obj || !val)
		goto done;
	if (!ASN1_STRING_set(val, der, der_len))
		goto done;
	ext = X509_EXTENSION_create_by_OBJ(NULL, obj, critical, val);
	if (!ext)
		goto done;
	if (X509_add_ext(cert, ext, -1))
		ret = 0;
done:
	ASN1_OBJECT_free(obj);
	ASN1_OCTET_STRING_free(val);
	X509_EXTENSION_free(ext);
	return ret;
}

/* ------------------------------------------------------------------ *
 * Add subjectAltName with PKINIT otherName (id-pkinit-san, critical).
 *
 * Uses the KRB5_PRINCIPAL_NAME ASN.1 type defined above with OpenSSL
 * macros, then encodes the result as an otherName GENERAL_NAME.
 * ------------------------------------------------------------------ */
int
add_pkinit_san(X509 *cert, const char *username, const char *realm)
{
	KRB5_PRINCIPAL_NAME  *krb5pn   = NULL;
	ASN1_GENERALSTRING   *realm_gs = NULL;
	ASN1_GENERALSTRING   *user_gs  = NULL;
	GENERAL_NAMES        *gens     = NULL;
	GENERAL_NAME         *gen      = NULL;
	ASN1_TYPE            *san_val  = NULL;
	unsigned char        *pn_der   = NULL;
	int                   pn_len;
	int                   ret      = -1;

	krb5pn = KRB5_PRINCIPAL_NAME_new();
	if (!krb5pn)
		goto done;

	/* realm [0] EXPLICIT GeneralString */
	realm_gs = ASN1_GENERALSTRING_new();
	if (!realm_gs ||
	    !ASN1_STRING_set(realm_gs, realm, (int)strlen(realm)))
		goto done;
	krb5pn->realm = realm_gs;
	realm_gs = NULL;

	/* principalName [1] EXPLICIT PrincipalName */
	krb5pn->principal_name = KRB5_PRINC_NAME_new();
	if (!krb5pn->principal_name)
		goto done;

	/* name-type [0] EXPLICIT INTEGER — KRB_NT_ENTERPRISE_PRINCIPAL = 10 */
	if (!ASN1_INTEGER_set(krb5pn->principal_name->name_type, 10))
		goto done;

	/* name-string [1] EXPLICIT SEQUENCE OF GeneralString */
	krb5pn->principal_name->name_string = KRB5_KERBEROS_STRINGS_new();
	if (!krb5pn->principal_name->name_string)
		goto done;

	user_gs = ASN1_GENERALSTRING_new();
	if (!user_gs ||
	    !ASN1_STRING_set(user_gs, username, (int)strlen(username)))
		goto done;
	if (!sk_ASN1_GENERALSTRING_push(krb5pn->principal_name->name_string,
	    user_gs))
		goto done;
	user_gs = NULL;  /* now owned by the stack */

	/* DER-encode KRB5_PRINCIPAL_NAME; OpenSSL allocates when *pp == NULL */
	pn_len = i2d_KRB5_PRINCIPAL_NAME(krb5pn, &pn_der);
	if (pn_len <= 0)
		goto done;

	/*
	 * d2i_ASN1_TYPE parses the full DER: reads the SEQUENCE tag+len and
	 * stores only the contents in value.sequence.  OpenSSL re-adds the
	 * 0x30 wrapper when serialising the OTHERNAME value field.
	 */
	{
		const unsigned char *p = pn_der;
		san_val = d2i_ASN1_TYPE(NULL, &p, (long)pn_len);
	}
	if (!san_val || san_val->type != V_ASN1_SEQUENCE)
		goto done;

	gen = GENERAL_NAME_new();
	if (!gen)
		goto done;
	gen->type = GEN_OTHERNAME;
	gen->d.otherName = OTHERNAME_new();
	if (!gen->d.otherName)
		goto done;
	gen->d.otherName->type_id = OBJ_txt2obj(OID_PKINIT_SAN, 1);
	if (!gen->d.otherName->type_id)
		goto done;
	gen->d.otherName->value = san_val;
	san_val = NULL;

	gens = GENERAL_NAMES_new();
	if (!gens || !sk_GENERAL_NAME_push(gens, gen))
		goto done;
	gen = NULL;

	/* critical = 1 per the design */
	if (X509_add1_ext_i2d(cert, NID_subject_alt_name, gens, 1, 0) == 1)
		ret = 0;

done:
	KRB5_PRINCIPAL_NAME_free(krb5pn);
	ASN1_GENERALSTRING_free(realm_gs);
	ASN1_GENERALSTRING_free(user_gs);
	GENERAL_NAMES_free(gens);
	GENERAL_NAME_free(gen);
	ASN1_TYPE_free(san_val);
	OPENSSL_free(pn_der);
	return ret;
}

#endif /* GSSAPI && KRB5 && !HEIMDAL && WITH_OPENSSL */
