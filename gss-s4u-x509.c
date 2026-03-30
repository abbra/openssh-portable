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
 * SSH S4U2Self X.509 attestation certificate construction.
 *
 * Builds a short-lived X.509 certificate encoding the SSH authentication
 * event, signed with a key derived from the host Kerberos keytab.  The
 * certificate is passed as subject_cert in a PA-FOR-X509-USER TGS-REQ so
 * that the KDC KDB plugin can verify the attestation and inject auth
 * indicators into the resulting service ticket.
 *
 * Design: ~/todo/ssh-s4u2self-binding.md
 * Server-side counterpart: ipa_kdb_s4u_x509.c in the IPA KDB plugin.
 */

#include "includes.h"

#if defined(GSSAPI) && defined(KRB5) && !defined(HEIMDAL) && defined(WITH_OPENSSL)

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/rand.h>

#include <krb5.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "crypto_api.h"
#include "sshkey.h"
#include "log.h"

#include "gss-s4u-x509.h"

/* OIDs for custom X.509 extensions (under the IPA Kerberos cert sub-arc) */
#define OID_SSH_ISSUER_BINDING   "2.16.840.1.113730.3.8.15.3.1"
#define OID_SSH_AUTHN_INFO       "2.16.840.1.113730.3.8.15.3.2"

/* OID for PKINIT SubjectAlternativeName (id-pkinit-san) */
#define OID_PKINIT_SAN           "1.3.6.1.5.2.2"

/* OID for id-pkinit-KPClientAuth extended key usage */
#define OID_PKINIT_KP_CLIENTAUTH "1.3.6.1.5.2.3.4"

#define BINDING_LABEL            "ssh-attestation-binding-v1"
#define HKDF_SALT                "ssh-attestation-v1"

/* Keytab path — same one gss_acquire_cred_from uses */
#define SSH_KEYTAB_PATH          "/etc/krb5.keytab"

/*
 * Preference order for keytab enctype (higher = more preferred).
 * Enctypes below 17 (DES/RC4) and unknown ones return 0 (reject).
 */
static int
enctype_preference(krb5_enctype e)
{
	switch (e) {
	case 20: return 4;	/* AES256-CTS-HMAC-SHA384-192 */
	case 19: return 3;	/* AES128-CTS-HMAC-SHA384-192 */
	case 18: return 2;	/* AES256-CTS-HMAC-SHA1-96 */
	case 17: return 1;	/* AES128-CTS-HMAC-SHA1-96 */
	default: return 0;
	}
}

/* ------------------------------------------------------------------ *
 * HKDF-SHA256 via OpenSSL 3.x EVP_KDF
 * ------------------------------------------------------------------ */
static int
hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
    const char *salt, size_t salt_len,
    const unsigned char *info, size_t info_len,
    unsigned char *out, size_t out_len)
{
	EVP_KDF		*kdf  = NULL;
	EVP_KDF_CTX	*kctx = NULL;
	int		 ret  = -1;

	kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	if (!kdf)
		goto done;
	kctx = EVP_KDF_CTX_new(kdf);
	if (!kctx)
		goto done;

	OSSL_PARAM params[] = {
		OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
		    "SHA256", 0),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
		    (void *)ikm, ikm_len),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
		    (void *)salt, salt_len),
		OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
		    (void *)info, info_len),
		OSSL_PARAM_construct_end()
	};

	if (EVP_KDF_derive(kctx, out, out_len, params) > 0)
		ret = 0;
done:
	EVP_KDF_CTX_free(kctx);
	EVP_KDF_free(kdf);
	return ret;
}


/*
 * NIST P-256 group order n (FIPS 186-4 §D.1.2.3 / SEC2 §2.4.2).
 * Hard-coded to avoid EC_GROUP_* which is deprecated in OpenSSL 3.x.
 * This constant is defined by the curve spec and will never change.
 */
static const unsigned char P256_ORDER[32] = {
	0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x00,
	0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
	0xBC,0xE6,0xFA,0xAD, 0xA7,0x17,0x9E,0x84,
	0xF3,0xB9,0xCA,0xC2, 0xFC,0x63,0x25,0x51
};

/*
 * Derive a P-256 private key from 48 bytes of HKDF output.
 * NIST SP 800-56A Rev 3 §5.6.1.2.2 "extra bits" method:
 *   k = (seed mod (n−1)) + 1,  ensuring 1 ≤ k < n.
 */
static EVP_PKEY *
derive_p256_key(const unsigned char *seed48)
{
	BN_CTX		*ctx   = NULL;
	BIGNUM		*raw   = NULL;
	BIGNUM		*n     = NULL;
	BIGNUM		*nm1   = NULL;
	BIGNUM		*k     = NULL;
	EVP_PKEY_CTX	*pctx  = NULL;
	EVP_PKEY	*pkey  = NULL;
	unsigned char	 kbytes[32] = {0};

	ctx = BN_CTX_new();
	raw = BN_bin2bn(seed48, 48, NULL);
	n   = BN_bin2bn(P256_ORDER, sizeof(P256_ORDER), NULL);
	nm1 = BN_new();
	k   = BN_new();

	if (!ctx || !raw || !n || !nm1 || !k)
		goto out;
	if (!BN_copy(nm1, n) || !BN_sub_word(nm1, 1) ||
	    !BN_mod(k, raw, nm1, ctx) || !BN_add_word(k, 1) ||
	    BN_bn2binpad(k, kbytes, 32) != 32)
		goto out;

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (pctx && EVP_PKEY_fromdata_init(pctx) > 0) {
		OSSL_PARAM params[] = {
			OSSL_PARAM_construct_utf8_string(
			    OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0),
			OSSL_PARAM_construct_BN(
			    OSSL_PKEY_PARAM_PRIV_KEY, kbytes, 32),
			OSSL_PARAM_construct_end()
		};
		EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params);
	}
out:
	OPENSSL_cleanse(kbytes, sizeof(kbytes));
	EVP_PKEY_CTX_free(pctx);
	BN_CTX_free(ctx);
	BN_free(raw);
	BN_free(n);
	BN_free(nm1);
	BN_free(k);
	return pkey;
}

/* ------------------------------------------------------------------ *
 * Derive the attestation signing key from keytab key material.
 *
 * Non-FIPS: Ed25519 from 32-byte HKDF seed
 * FIPS:     ECDSA P-256, NIST SP 800-56A Rev 3 §5.6.1.2.2
 *           48-byte HKDF output, reduce mod (n_P256 - 1) + 1
 * ------------------------------------------------------------------ */
static EVP_PKEY *
derive_attestation_key(const unsigned char *ikm, size_t ikm_len,
    const char *hostname, const char *realm, uint32_t kvno, int fips_mode)
{
	unsigned char	 seed[48];
	size_t		 seed_len = fips_mode ? 48 : 32;
	uint32_t	 kvno_be  = htonl(kvno);
	struct sshbuf	*info     = NULL;
	EVP_PKEY	*pkey     = NULL;

	/* HKDF info = hostname || NUL || realm || NUL || kvno_be32 */
	info = sshbuf_new();
	if (info == NULL ||
	    sshbuf_put(info, hostname, strlen(hostname) + 1) != 0 ||
	    sshbuf_put(info, realm,    strlen(realm)    + 1) != 0 ||
	    sshbuf_put(info, &kvno_be, sizeof(kvno_be))      != 0 ||
	    hkdf_sha256(ikm, ikm_len, HKDF_SALT, strlen(HKDF_SALT),
	        sshbuf_ptr(info), sshbuf_len(info), seed, seed_len) != 0)
		goto done;

	pkey = fips_mode
	    ? derive_p256_key(seed)
	    : EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);

done:
	sshbuf_free(info);
	OPENSSL_cleanse(seed, sizeof(seed));
	return pkey;
}

/* ------------------------------------------------------------------ *
 * Convert an SSH host public key to X509_PUBKEY (SubjectPublicKeyInfo).
 * Returns a newly allocated X509_PUBKEY; caller must X509_PUBKEY_free().
 * ------------------------------------------------------------------ */
static X509_PUBKEY *
sshkey_to_x509_pubkey(const struct sshkey *key)
{
	EVP_PKEY	*pkey      = NULL;
	X509_PUBKEY	*spki      = NULL;
	int		 need_free = 0;

	switch (key->type) {
	case KEY_RSA:
	case KEY_ECDSA:
		pkey = key->pkey;
		break;
	case KEY_ED25519:
		if (!key->ed25519_pk)
			return NULL;
		pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
		    key->ed25519_pk, ED25519_PK_SZ);
		need_free = 1;
		break;
	default:
		return NULL;
	}
	if (!pkey)
		return NULL;

	X509_PUBKEY_set(&spki, pkey);
	if (need_free)
		EVP_PKEY_free(pkey);
	return spki;
}

/* ------------------------------------------------------------------ *
 * Compute binding digest:
 *   SHA256(sshHostKey_SPKI_DER || BINDING_LABEL || principal || kvno_be32)
 * ------------------------------------------------------------------ */
static int
compute_binding_digest(X509_PUBKEY *spki, const char *principal,
    uint32_t kvno, unsigned char digest[SHA256_DIGEST_LENGTH])
{
	unsigned char	*spki_der = NULL;
	int		 spki_len;
	uint32_t	 kvno_be  = htonl(kvno);
	struct sshbuf	*b        = NULL;
	unsigned int	 dlen     = SHA256_DIGEST_LENGTH;
	int		 ret      = -1;

	spki_len = i2d_X509_PUBKEY(spki, &spki_der);
	if (spki_len <= 0)
		return -1;

	b = sshbuf_new();
	if (b == NULL ||
	    sshbuf_put(b, spki_der,     (size_t)spki_len)        != 0 ||
	    sshbuf_put(b, BINDING_LABEL, strlen(BINDING_LABEL))  != 0 ||
	    sshbuf_put(b, principal,    strlen(principal))        != 0 ||
	    sshbuf_put(b, &kvno_be,     sizeof(kvno_be))          != 0 ||
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
 * ASN.1 type definitions.
 *
 * These must match ipa_kdb_s4u_x509.c on the KDC side exactly.
 *
 * id-ce-sshKerberosIssuerBinding:
 *   SEQUENCE {
 *     version     INTEGER (0),
 *     principal   UTF8String,
 *     enctype     INTEGER,
 *     kvno        INTEGER,
 *     sigAlg      AlgorithmIdentifier,
 *     sshHostKey  SubjectPublicKeyInfo,
 *     binding     OCTET STRING
 *   }
 *
 * id-ce-sshAuthnInfo:
 *   SEQUENCE {
 *     version         INTEGER (0),
 *     authMethod      UTF8String,
 *     sessionId       OCTET STRING,
 *     keyFingerprint  [0] EXPLICIT UTF8String OPTIONAL,
 *     clientAddress   [1] EXPLICIT UTF8String OPTIONAL
 *   }
 *
 * KRB5PrincipalName (RFC 4556 / RFC 4120) for PKINIT subjectAltName:
 *   KRB5PrincipalName ::= SEQUENCE {
 *     realm         [0] EXPLICIT GeneralString,
 *     principalName [1] EXPLICIT PrincipalName
 *   }
 *   PrincipalName ::= SEQUENCE {
 *     name-type   [0] EXPLICIT INTEGER,
 *     name-string [1] EXPLICIT SEQUENCE OF GeneralString
 *   }
 * ------------------------------------------------------------------ */

typedef struct ssh_issuer_binding_st {
	ASN1_INTEGER      *version;
	ASN1_UTF8STRING   *principal;
	ASN1_INTEGER      *enctype;
	ASN1_INTEGER      *kvno;
	X509_ALGOR        *sig_alg;
	X509_PUBKEY       *ssh_host_key;
	ASN1_OCTET_STRING *binding;
} SSH_ISSUER_BINDING;

DECLARE_ASN1_FUNCTIONS(SSH_ISSUER_BINDING)

ASN1_SEQUENCE(SSH_ISSUER_BINDING) = {
	ASN1_SIMPLE(SSH_ISSUER_BINDING, version,      ASN1_INTEGER),
	ASN1_SIMPLE(SSH_ISSUER_BINDING, principal,    ASN1_UTF8STRING),
	ASN1_SIMPLE(SSH_ISSUER_BINDING, enctype,      ASN1_INTEGER),
	ASN1_SIMPLE(SSH_ISSUER_BINDING, kvno,         ASN1_INTEGER),
	ASN1_SIMPLE(SSH_ISSUER_BINDING, sig_alg,      X509_ALGOR),
	ASN1_SIMPLE(SSH_ISSUER_BINDING, ssh_host_key, X509_PUBKEY),
	ASN1_SIMPLE(SSH_ISSUER_BINDING, binding,      ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SSH_ISSUER_BINDING)

IMPLEMENT_ASN1_FUNCTIONS(SSH_ISSUER_BINDING)

typedef struct ssh_authn_info_st {
	ASN1_INTEGER      *version;
	ASN1_UTF8STRING   *auth_method;
	ASN1_OCTET_STRING *session_id;
	ASN1_UTF8STRING   *key_fingerprint;  /* [0] EXPLICIT OPTIONAL */
	ASN1_UTF8STRING   *client_address;   /* [1] EXPLICIT OPTIONAL */
} SSH_AUTHN_INFO;

DECLARE_ASN1_FUNCTIONS(SSH_AUTHN_INFO)

ASN1_SEQUENCE(SSH_AUTHN_INFO) = {
	ASN1_SIMPLE(SSH_AUTHN_INFO, version,         ASN1_INTEGER),
	ASN1_SIMPLE(SSH_AUTHN_INFO, auth_method,     ASN1_UTF8STRING),
	ASN1_SIMPLE(SSH_AUTHN_INFO, session_id,      ASN1_OCTET_STRING),
	ASN1_EXP_OPT(SSH_AUTHN_INFO, key_fingerprint, ASN1_UTF8STRING, 0),
	ASN1_EXP_OPT(SSH_AUTHN_INFO, client_address,  ASN1_UTF8STRING, 1),
} ASN1_SEQUENCE_END(SSH_AUTHN_INFO)

IMPLEMENT_ASN1_FUNCTIONS(SSH_AUTHN_INFO)

/*
 * PrincipalName inner type.
 * name-string is SEQUENCE OF GeneralString; we model it as a STACK_OF
 * ASN1_GENERALSTRING via the ASN1_ITEM_TEMPLATE mechanism.
 */
typedef STACK_OF(ASN1_GENERALSTRING) KRB5_KERBEROS_STRINGS;

ASN1_ITEM_TEMPLATE(KRB5_KERBEROS_STRINGS) =
	ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
	    KRB5_KERBEROS_STRINGS, ASN1_GENERALSTRING)
ASN1_ITEM_TEMPLATE_END(KRB5_KERBEROS_STRINGS)

IMPLEMENT_ASN1_ALLOC_FUNCTIONS(KRB5_KERBEROS_STRINGS)

typedef struct krb5_princ_name_st {
	ASN1_INTEGER         *name_type;    /* [0] EXPLICIT INTEGER */
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
 * Add a custom extension with a raw DER-encoded value.
 * ------------------------------------------------------------------ */
static int
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
 * Generate an ephemeral subject key for non-pubkey auth methods.
 * Returns a new EVP_PKEY; caller must EVP_PKEY_free().
 * ------------------------------------------------------------------ */
static EVP_PKEY *
generate_ephemeral_key(int fips_mode)
{
	if (!fips_mode)
		return EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
	return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
}

/* ------------------------------------------------------------------ *
 * Add subjectAltName with PKINIT otherName (id-pkinit-san, critical).
 *
 * Uses the KRB5_PRINCIPAL_NAME ASN.1 type defined above with OpenSSL
 * macros, then encodes the result as an otherName GENERAL_NAME.
 * ------------------------------------------------------------------ */
static int
add_pkinit_san(X509 *cert, const char *username, const char *realm)
{
	KRB5_PRINCIPAL_NAME  *krb5pn   = NULL;
	ASN1_GENERALSTRING   *realm_gs = NULL;
	ASN1_GENERALSTRING   *user_gs  = NULL;
	GENERAL_NAMES        *gens     = NULL;
	GENERAL_NAME         *gen      = NULL;
	ASN1_OBJECT          *san_oid  = NULL;
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

	/* name-type [0] EXPLICIT INTEGER — KRB_NT_PRINCIPAL = 1 */
	if (!ASN1_INTEGER_set(krb5pn->principal_name->name_type, 1))
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
	 * The otherName value is [0] EXPLICIT ANY where ANY = the encoded
	 * KRB5PrincipalName SEQUENCE.  OpenSSL's OTHERNAME.value is an
	 * ASN1_TYPE; set it to V_ASN1_SEQUENCE with the DER content bytes
	 * (i.e. the SEQUENCE contents, not including the outer tag+len that
	 * OpenSSL will re-add when encoding the OTHERNAME).
	 *
	 * We store the full DER (tag + len + contents) as V_ASN1_SEQUENCE
	 * data; OpenSSL re-wraps it correctly inside the otherName encoding.
	 */
	san_val = ASN1_TYPE_new();
	if (!san_val)
		goto done;
	san_val->type = V_ASN1_SEQUENCE;
	san_val->value.sequence = ASN1_STRING_new();
	if (!san_val->value.sequence)
		goto done;
	/*
	 * Strip the outer SEQUENCE tag+len from pn_der so that OpenSSL's
	 * ASN1_TYPE V_ASN1_SEQUENCE stores only the contents bytes; it will
	 * re-add tag 0x30 and the length when serialising the OTHERNAME.
	 */
	{
		const unsigned char *p = pn_der;
		long contents_len;
		int tag, cls;
		int hdr_len;

		/* Peek at the outer tag/length to find where contents begin */
		hdr_len = ASN1_get_object(&p, &contents_len, &tag, &cls,
		    pn_len);
		if (hdr_len & 0x80 || tag != V_ASN1_SEQUENCE)
			goto done;
		/* p now points at the contents; contents_len is their length */
		if (!ASN1_STRING_set(san_val->value.sequence,
		    p, (int)contents_len))
			goto done;
	}

	san_oid = OBJ_txt2obj(OID_PKINIT_SAN, 1);
	if (!san_oid)
		goto done;

	gen = GENERAL_NAME_new();
	if (!gen)
		goto done;
	gen->type = GEN_OTHERNAME;
	gen->d.otherName = OTHERNAME_new();
	if (!gen->d.otherName)
		goto done;
	gen->d.otherName->type_id = san_oid;
	san_oid = NULL;
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
	ASN1_OBJECT_free(san_oid);
	ASN1_TYPE_free(san_val);
	OPENSSL_free(pn_der);
	return ret;
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
		debug_f("S4U X.509: cannot parse host principal %s", princ_str);
		free(princ_str);
		return -1;
	}
	free(princ_str);

	if (krb5_kt_resolve(ctx, SSH_KEYTAB_PATH, &kt) != 0) {
		debug_f("S4U X.509: cannot open keytab %s", SSH_KEYTAB_PATH);
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
			/* AES-128 enctypes rejected in FIPS mode */
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
		debug_f("S4U X.509: no suitable keytab entry found");
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
	debug_f("S4U X.509: selected keytab entry enctype=%d kvno=%u "
	    "keylen=%zu for host/%s@%s",
	    (int)*enctype_out, *kvno_out, *ikm_len_out, hostname, realm);
	ret = 0;

done:
	krb5_kt_close(ctx, kt);
	krb5_free_principal(ctx, host_princ);
	return ret;
}

/* ------------------------------------------------------------------ *
 * Build the DER-encoded attestation certificate.
 *
 * On success, *cert_der_out is set to a malloc'd buffer of
 * *cert_der_len_out bytes.  Returns 0 on success, -1 on failure.
 * ------------------------------------------------------------------ */
int
ssh_gssapi_s4u_x509_build_cert(
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
    unsigned char **cert_der_out, size_t *cert_der_len_out)
{
	int		 fips_mode;
	EVP_PKEY	*derived_key  = NULL;
	EVP_PKEY	*subject_pkey = NULL;
	X509_PUBKEY	*host_spki    = NULL;
	X509		*cert         = NULL;
	char		*principal    = NULL;
	unsigned char	*ib_der = NULL, *ai_der = NULL;
	int		 ib_len = 0,     ai_len = 0;
	unsigned char	*cert_der = NULL;
	int		 cert_der_len;
	int		 key_id   = 0;
	const EVP_MD	*sign_md  = NULL;
	int		 ret = -1;

	*cert_der_out     = NULL;
	*cert_der_len_out = 0;

	fips_mode = EVP_default_properties_is_fips_enabled(NULL);

	/* In FIPS mode, Ed25519 client keys cannot go into a SPKI */
	if (fips_mode && auth_method_key != NULL &&
	    auth_method_key->type == KEY_ED25519) {
		debug_f("S4U X.509: Ed25519 client key not usable in FIPS "
		    "mode; falling back to plain S4U2Self");
		return -1;
	}

	xasprintf(&principal, "host/%s@%s", hostname, realm);

	derived_key = derive_attestation_key(ikm, ikm_len,
	    hostname, realm, kvno, fips_mode);
	if (!derived_key) {
		debug_f("S4U X.509: key derivation failed");
		goto done;
	}
	key_id  = EVP_PKEY_base_id(derived_key);
	sign_md = (key_id == EVP_PKEY_ED25519) ? NULL : EVP_sha256();

	host_spki = sshkey_to_x509_pubkey(host_pubkey);
	if (!host_spki) {
		debug_f("S4U X.509: cannot convert host key to SPKI");
		goto done;
	}

	/* ---- Build id-ce-sshKerberosIssuerBinding ---- */
	{
		SSH_ISSUER_BINDING *ib;
		unsigned char   digest[SHA256_DIGEST_LENGTH];
		unsigned char   sig[128]; /* Ed25519 = 64, ECDSA P-256 ≤ 72 */
		size_t          siglen = sizeof(sig);
		EVP_MD_CTX     *mdctx = NULL;

		ib = SSH_ISSUER_BINDING_new();
		if (!ib)
			goto done;

		if (!ASN1_INTEGER_set(ib->version, 0) ||
		    !ASN1_STRING_set(ib->principal, principal,
		        (int)strlen(principal)) ||
		    !ASN1_INTEGER_set(ib->enctype, (long)enctype) ||
		    !ASN1_INTEGER_set(ib->kvno, (long)kvno)) {
			SSH_ISSUER_BINDING_free(ib);
			goto done;
		}

		X509_ALGOR_set0(ib->sig_alg,
		    OBJ_nid2obj(key_id == EVP_PKEY_ED25519
		        ? NID_ED25519 : NID_ecdsa_with_SHA256),
		    V_ASN1_UNDEF, NULL);

		/* Transfer host_spki ownership into ib */
		X509_PUBKEY_free(ib->ssh_host_key);
		ib->ssh_host_key = host_spki;
		host_spki = NULL;

		if (compute_binding_digest(ib->ssh_host_key, principal,
		    kvno, digest) != 0) {
			ib->ssh_host_key = NULL;
			SSH_ISSUER_BINDING_free(ib);
			goto done;
		}

		mdctx = EVP_MD_CTX_new();
		if (!mdctx) {
			ib->ssh_host_key = NULL;
			SSH_ISSUER_BINDING_free(ib);
			goto done;
		}
		if (EVP_DigestSignInit(mdctx, NULL, sign_md, NULL,
		    derived_key) <= 0 ||
		    EVP_DigestSign(mdctx, sig, &siglen,
		        digest, SHA256_DIGEST_LENGTH) <= 0 ||
		    !ASN1_STRING_set(ib->binding, sig, (int)siglen)) {
			EVP_MD_CTX_free(mdctx);
			ib->ssh_host_key = NULL;
			SSH_ISSUER_BINDING_free(ib);
			goto done;
		}
		EVP_MD_CTX_free(mdctx);

		ib_len = i2d_SSH_ISSUER_BINDING(ib, &ib_der);
		ib->ssh_host_key = NULL;
		SSH_ISSUER_BINDING_free(ib);

		if (!ib_der || ib_len <= 0)
			goto done;
	}

	/* ---- Build id-ce-sshAuthnInfo ---- */
	{
		SSH_AUTHN_INFO *ai = SSH_AUTHN_INFO_new();
		if (!ai)
			goto done;

		const unsigned char *sid     = sshbuf_ptr(session_id_buf);
		size_t		     sid_len = sshbuf_len(session_id_buf);

		if (!ASN1_INTEGER_set(ai->version, 0) ||
		    !ASN1_STRING_set(ai->auth_method, auth_method,
		        (int)strlen(auth_method)) ||
		    !ASN1_STRING_set(ai->session_id, sid, (int)sid_len)) {
			SSH_AUTHN_INFO_free(ai);
			goto done;
		}
		if (key_fingerprint) {
			if (!ai->key_fingerprint)
				ai->key_fingerprint = ASN1_UTF8STRING_new();
			if (!ai->key_fingerprint ||
			    !ASN1_STRING_set(ai->key_fingerprint,
			        key_fingerprint, (int)strlen(key_fingerprint))) {
				SSH_AUTHN_INFO_free(ai);
				goto done;
			}
		}
		if (client_address) {
			if (!ai->client_address)
				ai->client_address = ASN1_UTF8STRING_new();
			if (!ai->client_address ||
			    !ASN1_STRING_set(ai->client_address,
			        client_address, (int)strlen(client_address))) {
				SSH_AUTHN_INFO_free(ai);
				goto done;
			}
		}

		ai_len = i2d_SSH_AUTHN_INFO(ai, &ai_der);
		SSH_AUTHN_INFO_free(ai);

		if (!ai_der || ai_len <= 0)
			goto done;
	}

	/* ---- Assemble X.509 certificate ---- */
	cert = X509_new();
	if (!cert)
		goto done;

	X509_set_version(cert, X509_VERSION_3);

	/* Random positive serial number */
	{
		uint64_t serial;
		RAND_bytes((unsigned char *)&serial, sizeof(serial));
		serial &= ~((uint64_t)1 << 63);	/* clear sign bit */
		ASN1_INTEGER_set_uint64(X509_get_serialNumber(cert), serial);
	}

	{
		time_t now = time(NULL);
		ASN1_TIME_set(X509_getm_notBefore(cert), now);
		ASN1_TIME_set(X509_getm_notAfter(cert),
		    now + (time_t)cert_lifetime);
	}

	/* Issuer: CN = "host/hostname@REALM" */
	X509_NAME_add_entry_by_NID(X509_get_issuer_name(cert),
	    NID_commonName, MBSTRING_UTF8,
	    (unsigned char *)principal, (int)strlen(principal), -1, 0);

	/* Subject: CN = user */
	X509_NAME_add_entry_by_NID(X509_get_subject_name(cert),
	    NID_commonName, MBSTRING_UTF8,
	    (unsigned char *)user, (int)strlen(user), -1, 0);

	/* SubjectPublicKeyInfo */
	if (auth_method_key != NULL &&
	    (auth_method_key->type == KEY_RSA ||
	     auth_method_key->type == KEY_ECDSA)) {
		X509_set_pubkey(cert, auth_method_key->pkey);
	} else if (auth_method_key != NULL &&
	    auth_method_key->type == KEY_ED25519 && !fips_mode) {
		EVP_PKEY *epkey = EVP_PKEY_new_raw_public_key(
		    EVP_PKEY_ED25519, NULL,
		    auth_method_key->ed25519_pk, ED25519_PK_SZ);
		if (epkey) {
			X509_set_pubkey(cert, epkey);
			EVP_PKEY_free(epkey);
		}
	} else {
		subject_pkey = generate_ephemeral_key(fips_mode);
		if (!subject_pkey)
			goto done;
		X509_set_pubkey(cert, subject_pkey);
	}

	/* basicConstraints: CA:FALSE (critical) */
	{
		X509V3_CTX v3ctx;
		X509V3_set_ctx_nodb(&v3ctx);
		X509V3_set_ctx(&v3ctx, NULL, cert, NULL, NULL, 0);
		X509_EXTENSION *bc = X509V3_EXT_conf_nid(NULL, &v3ctx,
		    NID_basic_constraints, "critical,CA:FALSE");
		if (bc) {
			X509_add_ext(cert, bc, -1);
			X509_EXTENSION_free(bc);
		}
	}

	/* keyUsage: digitalSignature (critical) */
	{
		X509V3_CTX v3ctx;
		X509V3_set_ctx_nodb(&v3ctx);
		X509V3_set_ctx(&v3ctx, NULL, cert, NULL, NULL, 0);
		X509_EXTENSION *ku = X509V3_EXT_conf_nid(NULL, &v3ctx,
		    NID_key_usage, "critical,digitalSignature");
		if (ku) {
			X509_add_ext(cert, ku, -1);
			X509_EXTENSION_free(ku);
		}
	}

	/* extKeyUsage: id-pkinit-KPClientAuth */
	{
		ASN1_OBJECT *eku_obj =
		    OBJ_txt2obj(OID_PKINIT_KP_CLIENTAUTH, 1);
		if (eku_obj) {
			EXTENDED_KEY_USAGE *eku = sk_ASN1_OBJECT_new_null();
			if (eku) {
				sk_ASN1_OBJECT_push(eku, eku_obj);
				eku_obj = NULL;
				X509_add1_ext_i2d(cert, NID_ext_key_usage,
				    eku, 0, 0);
				sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
			} else {
				ASN1_OBJECT_free(eku_obj);
			}
		}
	}

	/* subjectAltName: id-pkinit-san (critical) */
	if (add_pkinit_san(cert, user, realm) != 0)
		debug_f("S4U X.509: warning: failed to add PKINIT SAN");

	/* id-ce-sshKerberosIssuerBinding */
	if (add_raw_extension(cert, OID_SSH_ISSUER_BINDING, 0,
	    ib_der, ib_len) != 0) {
		debug_f("S4U X.509: cannot add issuer binding extension");
		goto done;
	}

	/* id-ce-sshAuthnInfo */
	if (add_raw_extension(cert, OID_SSH_AUTHN_INFO, 0,
	    ai_der, ai_len) != 0) {
		debug_f("S4U X.509: cannot add authn info extension");
		goto done;
	}

	/* Sign with the derived attestation key */
	if (X509_sign(cert, derived_key, sign_md) <= 0) {
		debug_f("S4U X.509: cert signing failed");
		goto done;
	}

	/* DER-encode the completed certificate */
	cert_der_len = i2d_X509(cert, NULL);
	if (cert_der_len <= 0)
		goto done;
	cert_der = malloc((size_t)cert_der_len);
	if (!cert_der)
		goto done;
	{
		unsigned char *p = cert_der;
		i2d_X509(cert, &p);
	}

	*cert_der_out     = cert_der;
	*cert_der_len_out = (size_t)cert_der_len;
	cert_der = NULL;
	debug_f("S4U X.509: built attestation cert for user %.100s "
	    "realm %.64s method %.32s (%d bytes)",
	    user, realm, auth_method, cert_der_len);
	ret = 0;

done:
	free(principal);
	OPENSSL_free(ib_der);
	OPENSSL_free(ai_der);
	free(cert_der);
	EVP_PKEY_free(derived_key);
	EVP_PKEY_free(subject_pkey);
	X509_PUBKEY_free(host_spki);
	X509_free(cert);
	return ret;
}

#endif /* GSSAPI && KRB5 && !HEIMDAL && WITH_OPENSSL */
