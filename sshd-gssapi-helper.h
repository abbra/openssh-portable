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
 * Wire protocol for ssh-gssapi-helper.
 *
 * All messages use the same framing as ssh-pkcs11-helper:
 *   [uint32 payload_length] [uint8 type] [sshbuf-encoded fields ...]
 *
 * The helper runs as a child of sshd-session, connected via a socketpair
 * whose ends are dup'd onto the helper's stdin/stdout.  One helper instance
 * serves exactly one authenticated SSH session.
 *
 * Privilege model
 * ---------------
 * The helper starts as root (to read the host keytab).  After a successful
 * IMPERSONATE it permanently drops to target_uid/target_gid via
 * seteuid/setegid and stays there for all subsequent operations.
 *
 * Request/response field layout
 * ------------------------------
 * IMPERSONATE request:
 *   string  user              (SSH login name)
 *   string  hostname          (server FQDN, used for keytab lookup)
 *   string  auth_method       ("publickey", "password", ...)
 *   string  client_address    ("ip:port", empty if unknown)
 *   string  key_fingerprint   ("SHA256:...", empty if not applicable)
 *   string  session_id        (binary blob)
 *   string  host_pubkey_blob  (SSH wire-format public key; empty = unavailable)
 *   string  client_key_blob   (SSH wire-format public key; empty = unavailable)
 *   uint32  lifetime          (requested ticket lifetime in seconds)
 *   uint32  target_uid
 *   uint32  target_gid
 *
 * IMPERSONATE success response:
 *   string  ccache_envval     (e.g. "FILE:/tmp/krb5cc_1000_XXXXXX")
 *   string  ccache_filename   (e.g. "/tmp/krb5cc_1000_XXXXXX"; empty for non-FILE)
 *   uint8   set_env           (1 = sshd should set KRB5CCNAME)
 *
 * DELEGATE request:
 *   uint32  nservices
 *   string  service[0 .. nservices-1]
 *   uint32  lifetime
 *
 * FILTER_CREDS request:
 *   uint32  filter_flags      (SSH_GSSAPI_HLP_FILTER_* bitmask)
 *   uint32  nservices
 *   string  service[0 .. nservices-1]
 *
 * CLEANUP request:   (no payload)
 *
 * Failure response:  (no payload; type byte only)
 * Success response with no data: (type byte only)
 */

#ifndef _SSHD_GSSAPI_HELPER_H
#define _SSHD_GSSAPI_HELPER_H

/* Safety cap on a single message */
#define SSH_GSSAPI_HLP_MAX_MSG          (256 * 1024)

/* How long sshd waits for the helper to respond (seconds) */
#define SSH_GSSAPI_HLP_TIMEOUT_SEC      30

/* Request types (sshd → helper) */
#define SSH_GSSAPI_HLP_IMPERSONATE      1
#define SSH_GSSAPI_HLP_DELEGATE         2
#define SSH_GSSAPI_HLP_FILTER_CREDS     3
#define SSH_GSSAPI_HLP_CLEANUP          4
#define SSH_GSSAPI_HLP_HANDOFF          5

/* Response types (helper → sshd) */
#define SSH_GSSAPI_HLP_SUCCESS          100
#define SSH_GSSAPI_HLP_FAILURE          101

/*
 * Filter flags for SSH_GSSAPI_HLP_FILTER_CREDS.
 * Values are deliberately identical to SSH_GSSAPI_CCFILTER_* in ssh-gss.h
 * so callers can pass them through unchanged.
 */
#define SSH_GSSAPI_HLP_FILTER_TGT       (1u << 0)
#define SSH_GSSAPI_HLP_FILTER_SELF      (1u << 1)
#define SSH_GSSAPI_HLP_FILTER_PROXY     (1u << 2)

#endif /* _SSHD_GSSAPI_HELPER_H */
