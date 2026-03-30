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
 * Cryptographic primitives for SSH S4U2Self X.509 attestation:
 *   - HKDF-SHA256 key derivation
 *   - P-256 private key derivation from seed (NIST SP 800-56A Rev 3)
 *   - Attestation signing key derivation (Ed25519 or P-256 in FIPS mode)
 *   - Ephemeral subject key generation
 */

#include "includes.h"

#if defined(GSSAPI) && defined(KRB5) && !defined(HEIMDAL) && defined(WITH_OPENSSL)

#include <sys/types.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

#include "sshbuf.h"
#include "log.h"

#include "gss-s4u-x509-internal.h"

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
	if (!kdf) {
		error_f("S4U X.509: EVP_KDF_fetch(HKDF) failed: %s",
		    ERR_reason_error_string(ERR_get_error()));
		goto done;
	}
	kctx = EVP_KDF_CTX_new(kdf);
	if (!kctx) {
		error_f("S4U X.509: EVP_KDF_CTX_new failed");
		goto done;
	}
	{
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
		else
			error_f("S4U X.509: EVP_KDF_derive failed: %s",
			    ERR_reason_error_string(ERR_get_error()));
	}
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
	/*
	 * raw is HKDF output derived from a secret keytab key.
	 * BN_FLG_CONSTTIME asks OpenSSL to prefer constant-time paths
	 * when raw is an operand.  BN_mod itself may not be fully
	 * constant-time in all OpenSSL versions; server-side exposure
	 * limits practical risk, but we set the flag as best effort.
	 */
	BN_set_flags(raw, BN_FLG_CONSTTIME);
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
		if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR,
		    params) <= 0)
			error_f("S4U X.509: EVP_PKEY_fromdata failed: %s",
			    ERR_reason_error_string(ERR_get_error()));
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
EVP_PKEY *
derive_attestation_key(const unsigned char *ikm, size_t ikm_len,
    const char *hostname, const char *realm, uint32_t kvno, int fips_mode,
    const char *hkdf_salt)
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
	    sshbuf_put(info, &kvno_be, sizeof(kvno_be))      != 0) {
		error_f("S4U X.509: HKDF info assembly failed");
		goto done;
	}
	if (hkdf_sha256(ikm, ikm_len, hkdf_salt, strlen(hkdf_salt),
	    sshbuf_ptr(info), sshbuf_len(info), seed, seed_len) != 0)
		goto done; /* hkdf_sha256 logs its own errors */

	pkey = fips_mode
	    ? derive_p256_key(seed)
	    : EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
	if (pkey == NULL)
		error_f("S4U X.509: %s key construction failed",
		    fips_mode ? "P-256" : "Ed25519");

done:
	sshbuf_free(info);
	OPENSSL_cleanse(seed, sizeof(seed));
	return pkey;
}

/* ------------------------------------------------------------------ *
 * Generate an ephemeral subject key for non-pubkey auth methods.
 * Returns a new EVP_PKEY; caller must EVP_PKEY_free().
 * ------------------------------------------------------------------ */
EVP_PKEY *
generate_ephemeral_key(int fips_mode)
{
	if (!fips_mode)
		return EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
	return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
}

#endif /* GSSAPI && KRB5 && !HEIMDAL && WITH_OPENSSL */
