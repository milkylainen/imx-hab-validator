/* Copyright (C) 2024 Christian Melki <christian.melki@westermo.com>
 * You may use, distribute and modify this code under the
 * terms of the LGPLv2.1 license.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define OPENSSL_API_COMPAT		0x10101000L
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "list.h"

/* Here's a basic/simplified overview of HABs CSF and IVT structure.
 * Caveat for any author misunderstandings.
 *
 * (Offsets are examples)  CSF, IVT and payload
 * 0x0               +---------------------------+
 *                   |        ...........        +
 * 0x1000            +---------------------------+---------------+
 *                   |  Image Vector Table (IVT) |     +------------------+
 *                   |         Boot Data         |     | Hashed and signed|
 *                   |  Device Config Data (DCD) |     |     One of the   |
 * 0x2000            +---------------------------+     | signatures in the|
 *                   |       Bootloader PBL      |     |        CSF       |
 *                   | Barebox contains piggy.o. |     |                  |
 *                   | Piggy is validated by PBL |     +---------v--------+
 * 0x28000           +---------------------------+---------------+
 *                   |         HAB CSF           |     +------------------+
 *                   |        Commands           |     | Hashed and signed|
 *                   |      Certificates         |     | HAB commands. A  |
 *                   |       Signatures          |     | sign. in the CSF |
 * 0xXXXXXX          +---------------------------+---- +---------v--------+
 */

/* A simplified description of the validation data flow.
 *   Bootloader + Code Signing Tool (CST)
 *            +------------+
 *            | Barebox PBL|
 *            |            |                                      +------------+
 *            +------------+                                      |Compare SRK |
 *                   |                                            |with table  |
 *            +------v-----+                                      +------^-----+
 *            | SHA256 hash|                                           /  \
 *            |            |   Signing cert                          /      \
 *            +------------+   private key              +------------+      +------------+
 *                   |           |                      | Chk. CSF   |      | Chk IVT+PBL|
 *            +------v-----+     |                      | with signer|      | with signer|
 *            | Sign with  |     |                      +------^-----+      +------^-----+
 *            | signing crt|<-----    Fused SRK table hash     \                   /
 *            +------------+                  |                  \               /
 *                   |                        v                    \           /
 *            +------v-----+            +------------+            +------------+
 *            |    IVT +   |            |            |            |  Find IVT  |
 *            |Barebox PBL+|----------->|  i.MX CPU  |----------->|  Find CSF  |
 *            |     CSF    |            |            |            | Parse CSF  |
 *            +------------+            +------------+            +------------+
 */

/* Defines taken from cst hab parser / extractor
 * These are tags, commands, information bits etc.
 */
#define HAB_TAG_IVT			0xD1 /* Image Vector Table HAB_TAG_IVT */
#define HAB_TAG_DCD			0xD2 /* Device Configuration Data HAB_TAG_DCD */
#define HAB_TAG_CSF			0xD4 /* Command Sequence File HAB_TAG_CSF */
#define HAB_TAG_CRT			0xD7 /* Certificate HAB_TAG_CRT */
#define HAB_TAG_SIG			0xD8 /* Signature HAB_TAG_SIG */
#define HAB_TAG_MAC			0xAC /* Message Authentication Code */

#define HAB_CMD_INS_KEY			0xBE /* Insert key command HAB_CMD_INS_KEY */
#define HAB_CMD_AUT_DAT			0xCA /* Authenticate Data command HAB_CMD_AUT_DAT */
#define HAB_CMD_SET			0xB1 /* Set command HAB_CMD_SET */
#define HAB_CMD_WRT_DAT			0xCC /* Write Data command HAB_CMD_WRT_DAT */
#define HAB_CMD_INIT			0xB4 /* Initialize command HAB_CMD_INIT */
#define HAB_CMD_UNLK			0xB2 /* Unlock command HAB_CMD_UNLK */

#define HAB_KEY_PUBLIC			0xE1 /* Public Key HAB_KEY_PUBLIC */
#define HAB_KEY_SECRET			0xE2 /* Secret Key HAB_KEY_SECRET */
#define HAB_KEY_MASTER			0xED /* Master Key Encryption Key HAB_KEY_MASTER */
#define HAB_KEY_HASH			0xEE /* Hash HAB_KEY_HASH */

#define HAB_ALG_PKCS1			0x21 /* PKCS#1 RSA signature algorithm	*/
#define HAB_ALG_ECDSA			0x27 /* NIST ECDSA signature algorithm */

#define HAB_VER_40			0x40 /* HAB 4.0 */
#define HAB_VER_45			0x45 /* HAB 4.5 */

#define HAB_ENG_ANY			0x00 /* Any HAB will chose the most appropriate engine */
#define HAB_ENG_CAAM			0x1D /* CAAM HAB_ENG_CAAM */
#define HAB_ENG_SNVS			0x1E /* Secure Non-Volatile Storage HAB_ENG_SNVS */
#define HAB_ENG_OCOTP			0x21 /* On Chip OTP memory HAB_ENG_OCOTP */
#define HAB_ENG_SW			0xFF /* Software Engine HAB_ENG_SW */
#define HAB_ENG_SAHARA			0x06 /* Crypto accelerator */
#define HAB_ENG_SCC			0x03 /* Security controller */
#define HAB_ENG_DCP			0x1b /* Data Co-Processor */
#define HAB_ENG_RTIC			0x05 /* Run-time integrity checker */
#define HAB_ENG_SRTC			0x0c /* Secure clock */

#define HAB_CMD_INS_KEY_NO_FLAG		0x00 /* No flags */
#define HAB_CMD_INS_KEY_ABS		0x01 /* Use absolute address for the key */
#define HAB_CMD_INS_KEY_CSF		0x02 /* Install CSF Key */

#define HAB_PCL_SRK			0x03 /* SRK format HAB_PCL_SRK */
#define HAB_PCL_X509			0x09 /* X509 format HAB_PCL_X509 */
#define HAB_PCL_BLOB			0xBB /* SHW-specific wrapped key format */

#define HAB_ALG_NO_ALG			0x00 /* No hash algorithm */
#define HAB_ALG_SHA1			0x11 /* SHA-1 algorithm ID */
#define HAB_ALG_SHA256			0x17 /* SHA-256 algorithm ID */
#define HAB_ALG_SHA512			0x1B /* SHA-512 algorithm ID */

#define HAB_CMD_AUT_DAT_NO_FLAG		0x00 /* No flags */
#define HAB_CMD_AUT_DAT_ABS		0x01 /* Use absolute address for the key */

#define HAB_CMD_AUT_DAT_PCL_CMS		0xC5
#define HAB_CMD_AUT_DAT_PCL_AEAD	0xA3 /* Proprietary AEAD MAC format */

#define MIN_AUT_DAT_CMD_LEN		12
#define HAB_DCP_BLOCK_MAX		6
#define HAB_SAHARA_BLOCK_MAX		12
#define HAB_CAAM_BLOCK_MAX		8
#define HAB_HDR_SIZE			4
#define HAB_UNLK_FEAT_MASK		0xF
#define HAB_VAR_CFG_ITM_ENG		0x03
#define HAB_ENG_CONF_MASK		0xDB

/* Minlen for total CSF unlikely to be < 256 bytes */
#define HAB_CSF_TOT_MIN_LEN		0x100
/* Maxlen for total CSF unlikely to be > 8192 bytes */
#define HAB_CSF_TOT_MAX_LEN		0x2000

/* Minlen for CMD unlikely to be < 32 bytes. */
#define HAB_CSF_CMD_MIN_LEN		0x20
/* Maxlen for CMD defined to be 768 bytes. */
#define HAB_CSF_CMD_MAX_LEN		0x300

/* IVT header magic */
#define IVT_HDR_VAL			0x402000d1
#define IVT_HDR_MASK			0xf0ffffff

#define SHA256_HEX_STR_LEN		64

/* HAB headers are 16-bit big endians. */
#define HAB_HDR_LEN(h)			be16toh(h->len)
/* Alignment things */
#define HAB_GET_ABS(h)			(HAB_HDR_LEN(h) & 3)

/* Wrapper to get __func_ correctly placed. */
#define dbprintf(...) dbvprintf(__func__, __VA_ARGS__)

/* Internal struct for pointers when parsing the HAB CSF */
typedef struct {
	uint8_t *rawbuf;
	size_t rawlen;
	uint8_t *buf;
	size_t len;
} habcsf_t;

/* Structs read by hw, created by CST, hence packed.
 * Do not poke these unless you know what you're doing.
 */
typedef struct {
	uint32_t header;
	uint32_t start;
	uint32_t res1;
	uint32_t dcd;
	uint32_t boot_data;
	uint32_t self;
	uint32_t csf;
	uint32_t res2;
} __attribute__((packed)) ivt_t;

typedef struct {
	uint8_t	 tag;
	uint16_t len;
	uint8_t	 version;
} __attribute__((packed)) csf_hdr_t;

typedef struct {
	uint8_t tag;
	uint16_t len;
	uint8_t flags;
} __attribute__((packed)) hab_hdr_t;

typedef struct {
	uint8_t cmd;
	uint16_t len;
	uint8_t flags;
	uint8_t cert_fmt;
	uint8_t hash_alg;
	uint8_t src_index;
	uint8_t tgt_index;
	uint32_t key_loc;
} __attribute__((packed)) csf_cmd_ins_key_t;

typedef struct {
	uint32_t address;
	uint32_t size;
} __attribute__((packed)) region_t;

typedef struct {
	uint8_t cmd;
	uint16_t len;
	uint8_t flags;
	uint8_t key;
	uint8_t sig_fmt;
	uint8_t engine;
	uint8_t eng_cfg;
	uint32_t sig_loc;
	region_t region[];
} __attribute__((packed)) csf_cmd_aut_dat_t;

typedef struct {
	uint8_t cmd;
	uint16_t len;
	uint8_t engine;
	uint32_t features;
	uint64_t uid;
} __attribute__((packed)) csf_cmd_unlock_t;

typedef struct {
	uint8_t cmd;
	uint16_t len;
	uint8_t cfg_itm;
	uint8_t res;
	uint8_t alg;
	uint8_t engine;
	uint8_t eng_cfg;
} __attribute__((packed)) csf_cmd_set_t;

typedef struct {
	uint8_t tag;
	uint16_t len;
	uint8_t version;
	uint8_t cert[];
} __attribute__((packed)) csf_sec_cert_t;

typedef struct {
	uint8_t tag;
	uint16_t len;
	uint8_t version;
	uint8_t sig[];
} __attribute__((packed)) csf_sec_sig_t;

typedef struct {
	uint8_t tag;
	uint16_t len;
	uint8_t version;
	uint8_t res1;
	uint8_t nonce_bytes;
	uint8_t res2;
	uint8_t mac_bytes;
	uint8_t nonce_mac[];
} __attribute__((packed)) csf_sec_mac_t;

/* Non CSF struct for pointing to super root key table keys */
typedef struct {
	uint8_t tag;
	uint16_t len;
	uint8_t version;
	uint8_t key[];
} __attribute__((packed)) csf_srktable_key_t;

/* Internal list handling */
typedef struct {
	uint8_t *buf;
	size_t buflen;
	struct list_head list;
} listtype_t;

static LIST_HEAD(srktablelist);
static LIST_HEAD(certlist);
static LIST_HEAD(signaturelist);

static int debug;

/* The two blocks to be verified.
 * the ivt+pbl starts from the head of
 * the IVT and encompasses all of the
 * payload (Barebox pbl) up until the csf.
 * The csf block is the csf cmd block.
 * Ie, the csf sec sections (certs etc).
 * are not validated (yes, apparently so?)
 */
static size_t ivtandpayload_offset;
static size_t ivtandpayload_len;
static size_t csfcmds_offset;
static size_t csfcmds_len;

/* Simple debug printf. */
static inline void
dbvprintf(const char *funcptr, const char *fmt, ...) {
	va_list ap;

	if (!debug) {
		return;
	}

	fprintf(stderr, "%-30s", funcptr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/* Count number of members in a list */
static inline size_t
list_count(struct list_head *head)
{
	struct list_head *pos;
	size_t count;

	if (!head) {
		goto err_out;
	}

	count = 0;
	list_for_each(pos, head) {
		count++;
	}

	return count;

err_out:
	return 0;
}

/* Finds a list member in a generic listtype_t
 * based on the contents of buf.
 */
static inline listtype_t *
find_list_entry(struct list_head *listhead, uint8_t *buf, size_t buflen)
{
	listtype_t *e;

	if (!listhead || !buf || !buflen) {
		goto err_out;
	}

	list_for_each_entry(e, listhead, list) {
		if (e->buflen &&
		    e->buflen == buflen &&
		    !memcmp(e->buf, buf, buflen)) {
			return e;
		}
	}

err_out:
	return NULL;
}

/* Free a list entry.
 * Free the buffer contents,
 * delink entry, free entry and
 * zero the pointer
 */
static inline void
free_list_entry(listtype_t *e)
{
	if (!e) {
		goto err_out;
	}

	if (e->buf) {
		free(e->buf);
	}
	list_del(&e->list);
	free(e);
	e = NULL;

err_out:
	return;
}

/* Free all entries.
 * Loop over a listhead,
 * calling free_list_entry.
 */
static inline int
free_list(struct list_head *listhead)
{
	listtype_t *e, *n;

	if (!listhead) {
		goto err_out;
	}
	list_for_each_entry_safe(e, n, listhead, list) {
		free_list_entry(e);
	}

	return 1;

err_out:
	return 0;
}

/* Allocates a list entry and adds it to the tail.
 * Allocates placement for the incoming buf.
 */
static listtype_t *
add_list_entry(struct list_head *listhead, uint8_t *buf, size_t buflen)
{
	listtype_t *e;
	size_t elen;

	e = NULL;
	if (!listhead || !buf || !buflen) {
		goto err_out;
	}

	if ((e = find_list_entry(listhead, buf, buflen))) {
		goto out;
	}
	elen = sizeof(listtype_t);
	if (!(e = malloc(elen))) {
		dbprintf("List memory alloc failed.\n");
		goto err_out;
	}
	memset(e, 0, elen);
	if (!(e->buf = malloc(buflen))) {
		dbprintf("List buffer memory alloc failed.\n");
		goto err_out;
	}
	memcpy(e->buf, buf, buflen);
	e->buflen = buflen;
	list_add_tail(&e->list, listhead);

out:
	return e;

err_out:
	if (e && e->buf) free(e->buf);
	if (e) free(e);
	return NULL;
}

/* CSF MAC SEC parsing.
 * Not really used in nonencrypted fast auth
 * but included anyway and checked for sanity.
 * Is NOT included in the CSF signature.
 */
static size_t
parse_mac_sec(uint8_t *csf_hdr, size_t csf_len, size_t offset)
{
	csf_sec_mac_t *mac_sec;

	mac_sec = (csf_sec_mac_t *)csf_hdr;

	if (!csf_hdr || !csf_len) {
		dbprintf("Invalid function params.\n");
		goto err_out;
	}
	if (mac_sec->tag != HAB_TAG_MAC) {
		dbprintf("Invalid tag.\n");
		goto err_out;
	}
	if (mac_sec->version < HAB_VER_40 ||
	    mac_sec->version > HAB_VER_45) {
		dbprintf("Invalid version.\n");
		goto err_out;
	}
	if ((offset + HAB_HDR_LEN(mac_sec)) > csf_len) {
		dbprintf("Invalid header len.\n");
		goto err_out;
	}
	if (HAB_HDR_LEN(mac_sec) != (mac_sec->nonce_bytes +
				     mac_sec->mac_bytes +
				     sizeof(csf_sec_mac_t))) {
		goto err_out;
	}

	dbprintf("Found mac sec. nonce bytes: %d, mac bytes %d\n",
		 mac_sec->nonce_bytes, mac_sec->mac_bytes);
	return HAB_HDR_LEN(mac_sec);

err_out:
	return 0;
}


/* CSF SIG SEC parsing.
 * Finds signatures and extracts them to the signature list.
 * Fast auth normally has two signatures. IVT+PBL and the CSF
 * Is NOT included in the CSF signature.
 */
static size_t
parse_sig_sec(uint8_t *csf_hdr, size_t csf_len, size_t offset)
{
	listtype_t *e;
	csf_sec_sig_t *sig_sec;
	size_t sig_sec_len;

	sig_sec = (csf_sec_sig_t *)csf_hdr;

	if (!csf_hdr || !csf_len) {
		dbprintf("Invalid function params.\n");
		goto err_out;
	}
	if (sig_sec->tag != HAB_TAG_SIG) {
		dbprintf("Invalid tag.\n");
		goto err_out;
	}
	if (sig_sec->version < HAB_VER_40 ||
	    sig_sec->version > HAB_VER_45) {
		dbprintf("Invalid version.\n");
		goto err_out;
	}
	if ((offset + HAB_HDR_LEN(sig_sec)) > csf_len) {
		dbprintf("Invalid header len.\n");
		goto err_out;
	}
	sig_sec_len = HAB_HDR_LEN(sig_sec);
	/* Yes. This is stupid. NXP aligned/padded to HDR_SIZE
	 * without fixing the header len declaration.
	 * Ie, the real data is HDR_LEN - HDR_SIZE, but the stored data is
	 * HDR_LEN + HDR_SIZE - aligning/padding.
	 */
	if (HAB_GET_ABS(sig_sec)) {
		sig_sec_len += HAB_HDR_SIZE - HAB_GET_ABS(sig_sec);
	}
	if (!(HAB_HDR_LEN(sig_sec) > HAB_HDR_SIZE)) {
		dbprintf("Invalid header len.\n");
		goto err_out;
	}
	e = add_list_entry(&signaturelist, sig_sec->sig,
			   HAB_HDR_LEN(sig_sec) - HAB_HDR_SIZE);
	if (!e) {
		goto err_out;
	}

	dbprintf("Found signature, length %zu\n", e->buflen);
	return sig_sec_len;

err_out:
	return 0;
}

/* CSF CERT SEC parsing.
 * Finds certs and extracts them to the cert list.
 * Fast auth normally has one cert. The SRK public half of
 * the signing cert.
 * Is NOT included in the CSF signature.
 */
static size_t
parse_cert_sec(uint8_t *csf_hdr, size_t csf_len, size_t offset)
{
	listtype_t *e;
	csf_sec_cert_t *cert_sec;
	size_t cert_sec_len;

	cert_sec = (csf_sec_cert_t *)csf_hdr;

	if (!csf_hdr || !csf_len) {
		dbprintf("Invalid function params.\n");
		goto err_out;
	}
	if (cert_sec->tag != HAB_TAG_CRT) {
		dbprintf("Invalid tag.\n");
		goto err_out;
	}
	if (cert_sec->version < HAB_VER_40 ||
	    cert_sec->version > HAB_VER_45) {
		dbprintf("Invalid version.\n");
		goto err_out;
	}
	if ((offset + HAB_HDR_LEN(cert_sec)) > csf_len) {
		dbprintf("Invalid header len.\n");
		goto err_out;
	}
	cert_sec_len = HAB_HDR_LEN(cert_sec);
	/* Yes. This is stupid. NXP aligned/padded to HDR_SIZE
	 * without fixing the header len declaration.
	 * Ie, the real data is HDR_LEN - HDR_SIZE, but the stored data is
	 * HDR_LEN + HDR_SIZE - aligning/padding.
	 */
	if (HAB_GET_ABS(cert_sec)) {
		cert_sec_len += HAB_HDR_SIZE - HAB_GET_ABS(cert_sec);
	}
	if (!(cert_sec->cert[0] == HAB_KEY_PUBLIC && \
	      (cert_sec->cert[3] == HAB_ALG_PKCS1 ||
	       cert_sec->cert[3] == HAB_ALG_ECDSA))) {
		if (!(HAB_HDR_LEN(cert_sec) > HAB_HDR_SIZE)) {
			dbprintf("Invalid header len.\n");
			goto err_out;
		}
		e = add_list_entry(&certlist, cert_sec->cert,
				   HAB_HDR_LEN(cert_sec) - HAB_HDR_SIZE);
		if (!e) {
			goto err_out;
		}
		dbprintf("Found cert with length: %zu\n", e->buflen);
	}

	return cert_sec_len;

err_out:
	return 0;
}

/* CSF SET CMD.
 * The SET cmd. Used by normal CSF.
 * Is included in the csf signature.
 */
static size_t
parse_set_cmd(uint8_t *csf_hdr, size_t csf_len, size_t offset)
{
	csf_cmd_set_t *set_cmd;

	set_cmd = (csf_cmd_set_t *)csf_hdr;

	if (!csf_hdr || !csf_len) {
		dbprintf("Invalid function params.\n");
		goto err_out;
	}
	if (set_cmd->cmd != HAB_CMD_SET) {
		dbprintf("Invalid tag.\n");
		goto err_out;
	}
	if (set_cmd->cfg_itm != HAB_VAR_CFG_ITM_ENG) {
		dbprintf("Invalid engine.\n");
		goto err_out;
	}
	if (set_cmd->alg != HAB_ALG_SHA1 &&
	    set_cmd->alg != HAB_ALG_SHA256 &&
	    set_cmd->alg != HAB_ALG_SHA512) {
		dbprintf("Invalid hash algo.\n");
		goto err_out;
	}
	if (set_cmd->engine != HAB_ENG_ANY &&
	    set_cmd->engine != HAB_ENG_CAAM &&
	    set_cmd->engine != HAB_ENG_DCP &&
	    set_cmd->engine != HAB_ENG_SAHARA &&
	    set_cmd->engine != HAB_ENG_RTIC &&
	    set_cmd->engine != HAB_ENG_SW) {
		dbprintf("Invalid engine.\n");
		goto err_out;
	}
	if ((offset + HAB_HDR_LEN(set_cmd)) > csf_len) {
		dbprintf("Invalid header len.\n");
		goto err_out;
	}
	if (set_cmd->eng_cfg & (uint8_t)~HAB_ENG_CONF_MASK) {
		dbprintf("Invalid engine config.\n");
		goto err_out;
	}

	return HAB_HDR_LEN(set_cmd);

err_out:
	return 0;
}

/* CSF UNLOCK CMD.
 * The UNLOCK / INIT cmd. Used by normal CSF.
 * Is included in the csf signature.
 */
static size_t
parse_unlock_cmd(uint8_t *csf_hdr, size_t csf_len, size_t offset)
{
	uint32_t ulck_features;
	csf_cmd_unlock_t *unlock_cmd;

	unlock_cmd = (csf_cmd_unlock_t *)csf_hdr;

	if (!csf_hdr || !csf_len) {
		dbprintf("Invalid function params.\n");
		goto err_out;
	}
	if (unlock_cmd->cmd != HAB_CMD_UNLK &&
	    unlock_cmd->cmd != HAB_CMD_INIT) {
		dbprintf("Invalid tag.\n");
		goto err_out;
	}
	if (unlock_cmd->engine != HAB_ENG_CAAM &&
	    unlock_cmd->engine != HAB_ENG_SNVS &&
	    unlock_cmd->engine != HAB_ENG_SRTC &&
	    unlock_cmd->engine != HAB_ENG_OCOTP) {
		dbprintf("Invalid engine.\n");
		goto err_out;
	}
	if ((offset + HAB_HDR_LEN(unlock_cmd)) > csf_len) {
		dbprintf("Invalid header len.\n");
		goto err_out;
	}
	/* Optional ? */
	if (HAB_HDR_LEN(unlock_cmd) > 4) {
		ulck_features = be32toh(unlock_cmd->features);
		if (ulck_features & (uint32_t)~HAB_UNLK_FEAT_MASK) {
			dbprintf("Invalid feature set.\n");
			goto err_out;
		}
	}

	return HAB_HDR_LEN(unlock_cmd);

err_out:
	return 0;
}

/* CSF AUT DAT CMD
 * The authenticate data cmd. Used by normal CSF.
 * Uses a bunch of sanity checks.
 * Is included in the csf signature.
 */
static size_t
parse_aut_dat_cmd(uint8_t *csf_hdr, size_t csf_len, size_t offset)
{
	csf_cmd_aut_dat_t *aut_dat_cmd_temp;
	csf_cmd_aut_dat_t *aut_dat_cmd;
	size_t nregions, aut_dat_len;

	nregions = 0;
	aut_dat_cmd = NULL;
	aut_dat_cmd_temp = (csf_cmd_aut_dat_t *)csf_hdr;

	if (!csf_hdr || !csf_len) {
		dbprintf("Invalid function params.\n");
		goto err_out;
	}
	if (HAB_HDR_LEN(aut_dat_cmd_temp) < MIN_AUT_DAT_CMD_LEN) {
		dbprintf("Invalid min length.\n");
		goto err_out;
	}
	if (HAB_HDR_LEN(aut_dat_cmd_temp) > MIN_AUT_DAT_CMD_LEN) {
		nregions = (HAB_HDR_LEN(aut_dat_cmd_temp) -
			    sizeof(csf_cmd_aut_dat_t)) / sizeof(region_t);
		if (nregions <= 0) {
			dbprintf("Invalid region size.\n");
			goto err_out;
		}
		dbprintf("Num regions %zu.\n", nregions);
	}
	if (aut_dat_cmd_temp->engine == HAB_ENG_CAAM) {
		if (nregions >= HAB_CAAM_BLOCK_MAX) {
			dbprintf("Invalid caam region max.\n");
			goto err_out;
		}
	} else if (aut_dat_cmd_temp->engine == HAB_ENG_DCP) {
		if (nregions >= HAB_DCP_BLOCK_MAX) {
			dbprintf("Invalid dcp region max.\n");
			goto err_out;
		}
	} else if (aut_dat_cmd_temp->engine == HAB_ENG_SAHARA) {
		if (nregions >= HAB_SAHARA_BLOCK_MAX) {
			dbprintf("Invalid sahara region max.\n");
			goto err_out;
		}
	}
	aut_dat_cmd = malloc(sizeof(csf_cmd_aut_dat_t) +
			     (nregions * sizeof(region_t)));
	if (!aut_dat_cmd) {
		dbprintf("Can't allocate buffer.\n");
		goto err_out;
	}
	memset(aut_dat_cmd, 0, sizeof(csf_cmd_aut_dat_t) +
	       (nregions * sizeof(region_t)));
	if (!memcpy(aut_dat_cmd, csf_hdr, HAB_HDR_LEN(aut_dat_cmd_temp))) {
		dbprintf("Failed to copy data to final.\n");
		goto err_out;
	}
	if (!aut_dat_cmd->key &&
	    aut_dat_cmd->sig_fmt != HAB_CMD_AUT_DAT_PCL_AEAD) {
		dbprintf("Fast Auth detected\n");
	}
	if (aut_dat_cmd->cmd != HAB_CMD_AUT_DAT) {
		dbprintf("Invalid command.\n");
		goto err_out;
	}
	if (aut_dat_cmd->flags != HAB_CMD_AUT_DAT_NO_FLAG &&
	    aut_dat_cmd->flags != HAB_CMD_AUT_DAT_ABS) {
		dbprintf("Invalid flags.\n");
		goto err_out;
	}
	if ((offset + HAB_HDR_LEN(aut_dat_cmd)) > csf_len) {
		dbprintf("Invalid header len.\n");
		goto err_out;
	}
	if (aut_dat_cmd->key > 4) {
		dbprintf("Invalid key number.\n");
		goto err_out;
	}
	if (aut_dat_cmd->sig_fmt != HAB_CMD_AUT_DAT_PCL_CMS &&
	    aut_dat_cmd->sig_fmt != HAB_CMD_AUT_DAT_PCL_AEAD) {
		dbprintf("Invalid signature format.\n");
		goto err_out;
	}
	if (aut_dat_cmd->engine != HAB_ENG_ANY &&
	    aut_dat_cmd->engine != HAB_ENG_CAAM &&
	    aut_dat_cmd->engine != HAB_ENG_DCP &&
	    aut_dat_cmd->engine != HAB_ENG_SAHARA &&
	    aut_dat_cmd->engine != HAB_ENG_SW) {
		dbprintf("Invalid engine.\n");
		goto err_out;
	}
	if (aut_dat_cmd->eng_cfg & (uint8_t)~HAB_ENG_CONF_MASK) {
		dbprintf("Invalid engine config.\n");
		goto err_out;
	}

	/* Holds authentication regions */
	aut_dat_len = HAB_HDR_LEN(aut_dat_cmd);
	free(aut_dat_cmd);
	return aut_dat_len;

err_out:
	if (aut_dat_cmd) free(aut_dat_cmd);
	return 0;
}

/* CSF INS KEY CMD
 * The insert key cmd. Used by normal CSF.
 * Inserts keys and also the SRK table through
 * a very "strange" mechanism, courtesy of NXP.
 * The SRK table is inserted in a srktable list.
 * Is included in the csf signature.
 */
static size_t
parse_ins_key_cmd(uint8_t *csf_hdr, size_t csf_len, size_t offset)
{
	listtype_t *e;
	csf_cmd_ins_key_t *ins_key_cmd;
	csf_sec_cert_t *cert_sec;
	size_t srktable_offset;

	ins_key_cmd = (csf_cmd_ins_key_t *)csf_hdr;

	if (!csf_hdr || !csf_len) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	if (ins_key_cmd->cmd != HAB_CMD_INS_KEY) {
		dbprintf("Invalid command.\n");
		goto err_out;
	}
	if (ins_key_cmd->flags != HAB_CMD_INS_KEY_NO_FLAG &&
	    ins_key_cmd->flags != HAB_CMD_INS_KEY_ABS &&
	    ins_key_cmd->flags != HAB_CMD_INS_KEY_CSF) {
		dbprintf("Invalid flags.\n");
		goto err_out;
	}
	if ((offset + HAB_HDR_LEN(ins_key_cmd)) > csf_len) {
		dbprintf("Invalid header len.\n");
		goto err_out;
	}
	if (ins_key_cmd->cert_fmt != HAB_PCL_SRK &&
	    ins_key_cmd->cert_fmt != HAB_PCL_X509 &&
	    ins_key_cmd->cert_fmt != HAB_PCL_BLOB) {
		dbprintf("Invalid cert format.\n");
		goto err_out;
	}
	if (ins_key_cmd->hash_alg != HAB_ALG_NO_ALG &&
	    ins_key_cmd->hash_alg != HAB_ALG_SHA256) {
		dbprintf("Invalid cert hash algo.\n");
		goto err_out;
	}
	if (ins_key_cmd->cert_fmt == HAB_PCL_SRK ||
	    ins_key_cmd->cert_fmt == HAB_PCL_BLOB) {
		if (ins_key_cmd->src_index > 3) {
			dbprintf("Invalid src idx for cert_fmt.\n");
			goto err_out;
		}
	} else {
		if (ins_key_cmd->src_index == 1 ||
		    ins_key_cmd->src_index > 5) {
			dbprintf("Invalid src idx for cert_fmt.\n");
			goto err_out;
		}
	}
	if (ins_key_cmd->cert_fmt == HAB_PCL_SRK) {
		if (ins_key_cmd->tgt_index != 0) {
			dbprintf("Invalid tgt idx for cert_fmt.\n");
			goto err_out;
		}
	} else if (ins_key_cmd->cert_fmt == HAB_PCL_BLOB) {
		if (ins_key_cmd->tgt_index > 3) {
			dbprintf("Invalid tgt idx for cert_fmt.\n");
			goto err_out;
		}
	} else {
		if (!ins_key_cmd->tgt_index ||
		    ins_key_cmd->tgt_index > 5) {
			dbprintf("Invalid tgt idx for cert_fmt.\n");
			goto err_out;
		}
	}

	if (ins_key_cmd->cert_fmt == HAB_PCL_SRK) {
		if (be32toh(ins_key_cmd->key_loc) < offset) {
			dbprintf("Invalid srktable offset.\n");
			goto err_out;
		}
		/* Wrap the srktable in a header that contains
		 * the normal header len. key_loc is not just the
		 * srktable in this case
		 */
		srktable_offset = be32toh(ins_key_cmd->key_loc) - offset;
		cert_sec = (csf_sec_cert_t *)&csf_hdr[srktable_offset];
		e = add_list_entry(&srktablelist, cert_sec->cert,
				   HAB_HDR_LEN(cert_sec) - HAB_HDR_SIZE);
		if (!e) {
			goto err_out;
		}
		dbprintf("Found srktable len %zu\n", e->buflen);
	} else if (ins_key_cmd->cert_fmt == HAB_PCL_X509) {
		/* Report which certificate is found */
		if (!ins_key_cmd->tgt_index) {
			dbprintf("SRK Certificate Detected\n");
		} else if (ins_key_cmd->tgt_index == 1) {
			dbprintf("CSF Certificate Detected\n");
		} else if (ins_key_cmd->tgt_index > 1 &&
			   ins_key_cmd->tgt_index < 6) {
			dbprintf("IMG Certificate Detected\n");
		}
	}

	return HAB_HDR_LEN(ins_key_cmd);

err_out:
	return 0;
}

/* CSF HDR
 * The csf header. Starts of the CSF.
 * Is included in the csf signature.
 */
static size_t
parse_csf_hdr(uint8_t *csf_hdr, size_t csf_len, size_t offset)
{
	csf_hdr_t *csf_header;

	csf_header = (csf_hdr_t *)csf_hdr;

	if (!csf_hdr || !csf_len) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	if (csf_header->tag != HAB_TAG_CSF) {
		dbprintf("Invalid tag.\n");
		goto err_out;
	}
	if (csf_header->version < HAB_VER_40 ||
	    csf_header->version > HAB_VER_45) {
		dbprintf("Invalid version.\n");
		goto err_out;
	}
	if ((offset + HAB_HDR_LEN(csf_header)) > csf_len) {
		dbprintf("Invalid header len.\n");
		goto err_out;
	}

	/* Return the header size, not the header length.
	 * This is intentional, so we can walk the TLV cmds.
	 */
	return sizeof(csf_hdr_t);

err_out:
	return 0;
}

/* Parse CSF.
 * Walks the CSF and finds tags in a
 * Type-Length-Value fashion.
 * The parsing has no normal termination but stops
 * when maximum length is exceeded or strangeness is
 * encountered.
 * The function keeps track of total length including
 * the non signed sec sections and also keeps track of
 * the cmd section for the signature process later on.
 */
static int
parse_csf(habcsf_t *hcsf)
{
	uint8_t *csf;
	size_t csf_len, hdr_len;
	size_t offset;

	if (!hcsf) {
		goto err_out;
	}
	csf = hcsf->buf;
	csf_len = hcsf->len;
	offset = 0;
	hdr_len = 0;

	while (offset < csf_len) {
		switch (csf[offset]) {
		case (HAB_TAG_CSF):
			dbprintf("parse_csf_hdr\n");
			hdr_len = parse_csf_hdr(&csf[offset],
						csf_len, offset);
			if (!hdr_len) {
				goto err_out;
			}
			/* Accumulate the command lengths */
			csfcmds_len += hdr_len;
			break;
		case (HAB_CMD_INS_KEY):
			dbprintf("parse_ins_key_cmd\n");
			hdr_len = parse_ins_key_cmd(&csf[offset],
						    csf_len, offset);
			if (!hdr_len) {
				goto err_out;
			}
			/* Accumulate the command lengths */
			csfcmds_len += hdr_len;
			break;
		case (HAB_CMD_AUT_DAT):
			dbprintf("parse_aut_dat_cmd\n");
			hdr_len = parse_aut_dat_cmd(&csf[offset],
						    csf_len, offset);
			if (!hdr_len) {
				goto err_out;
			}
			/* Accumulate the command lengths */
			csfcmds_len += hdr_len;
			break;
		case (HAB_CMD_INIT):
		case (HAB_CMD_UNLK):
			dbprintf("parse_unlock/init_cmd\n");
			hdr_len = parse_unlock_cmd(&csf[offset],
						   csf_len, offset);
			if (!hdr_len) {
				goto err_out;
			}
			/* Accumulate the command lengths */
			csfcmds_len += hdr_len;
			break;
		case (HAB_CMD_SET):
			dbprintf("parse_set_cmd\n");
			hdr_len = parse_set_cmd(&csf[offset],
						csf_len, offset);
			if (!hdr_len) {
				goto err_out;
			}
			/* Accumulate the command lengths */
			csfcmds_len += hdr_len;
			break;
		case (HAB_TAG_CRT):
			dbprintf("parse_cert_sec\n");
			hdr_len = parse_cert_sec(&csf[offset],
						 csf_len, offset);
			if (!hdr_len) {
				goto err_out;
			}
			break;
		case (HAB_TAG_SIG):
			dbprintf("parse_sig_sec\n");
			hdr_len = parse_sig_sec(&csf[offset],
						csf_len, offset);
			if (!hdr_len) {
				goto err_out;
			}
			break;
		case (HAB_TAG_MAC):
			dbprintf("parse_mac_sec\n");
			hdr_len = parse_mac_sec(&csf[offset],
						csf_len, offset);
			if (!hdr_len) {
				goto err_out;
			}
			break;
		default :
			/* csf parse has no natural exit.
			 * It always parses until first invalid
			 * byte. This is an NXP construction.
			 */
			dbprintf("Unknown data. Ending parse.\n");
			goto out;
		}

		dbprintf("Stepping %zu bytes in CSF\n", hdr_len);
		offset += hdr_len;
		dbprintf("Offset currently at %zu in CSF\n", offset);
	}

out:
	/* Sanity check lengths before we continue */
	if (offset < HAB_CSF_TOT_MIN_LEN ||
	    offset > HAB_CSF_TOT_MAX_LEN ||
	    csfcmds_len < HAB_CSF_CMD_MIN_LEN ||
	    csfcmds_len > HAB_CSF_CMD_MAX_LEN) {
		goto err_out;
	}
	return 1;

err_out:
	return 0;
}

/* extract csf.
 * Walks binary data. Finds the IVT entry and from that
 * concludes where to find the CSF.
 */
static uint8_t *
extract_csf(uint8_t *buf, size_t buf_size, size_t *csf_len)
{
	size_t csf_hdr_len, pos;
	size_t csf_pos;
	ivt_t *ivt;
	hab_hdr_t *hdr;

	pos = 0;
	ivt = (ivt_t *)buf;

	if (!buf || !buf_size || !csf_len) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	if (buf_size < sizeof(ivt_t)) {
		dbprintf("Invalid ivt size.\n");
		goto err_out;
	}
	/* Put an artificial limit for input
	 * at 16M. It's unlikely that the bootloader
	 * or payload IVT offset will grow above this.
	 */
	if (buf_size > (16 << 20)) {
		dbprintf("Could not find IVT. Offset too large.\n");
		goto err_out;
	}
	/* This walker is a bit naive */
	while ((ivt->header & IVT_HDR_MASK) != IVT_HDR_VAL) {
		pos += 4;
		if (pos > (buf_size - sizeof(ivt_t))) {
			dbprintf("IVT remainder data too small.\n");
			goto err_out;
		}
		ivt = (ivt_t *)&buf[pos];
	}
        dbprintf("IVT at offset   = 0x%08x\n", (int)pos);
        dbprintf("      HEADER    = 0x%08x\n", ivt->header);
        dbprintf("      START     = 0x%08x\n", ivt->start);
        dbprintf("      RES1      = 0x%08x\n", ivt->res1);
        dbprintf("      DCD       = 0x%08x\n", ivt->dcd);
        dbprintf("      BOOT DATA = 0x%08x\n", ivt->boot_data);
        dbprintf("      SELF      = 0x%08x\n", ivt->self);
        dbprintf("      CSF       = 0x%08x\n", ivt->csf);
        dbprintf("      RES2      = 0x%08x\n", ivt->res2);
	/* DCD shall be null. Broken auth flow may
	 * follow otherwise.
	 */
	if (ivt->dcd) {
		dbprintf("Invalid IVT, contains a DCD.\n");
		goto err_out;
	}
	if (!ivt->csf && !ivt->self) {
		dbprintf("Invalid IVT, csf or self corrupt.\n");
		goto err_out;
	}
	if (ivt->self >= ivt->csf) {
		dbprintf("Invalid IVT, self is after csf.\n");
		goto err_out;
	}
	csf_pos = pos + (ivt->csf - ivt->self);
	/* Store some data for the verifications.
	 * The ivtandpayload_offset starts at the ivt offset.
	 * The ivtandpayload_len is the csf start minus the ivt offset.
	 * The csfcmds_offset starts at the csf offset.
	 * Length of the commands is determined by parsing.
	 */
	ivtandpayload_offset = pos;
	ivtandpayload_len = csf_pos - pos;
	csfcmds_offset = csf_pos;
	if (ivt->csf && (csf_pos > (buf_size - sizeof(hab_hdr_t)))) {
		dbprintf("Invalid IVT, csf remainder data too small.\n");
		goto err_out;
	}
	hdr = (hab_hdr_t *)&buf[csf_pos];
	if (hdr->tag != HAB_TAG_CSF) {
		dbprintf("Invalid IVT, csf points to invalid csf header.\n");
		goto err_out;
	}
	csf_hdr_len = HAB_HDR_LEN(hdr);
	if ((csf_pos + csf_hdr_len) < buf_size) {
		*csf_len = buf_size - csf_pos;
		dbprintf("CSF found at offset = 0x%08x, len = %zu\n",
			 (int)csf_pos, *csf_len);
		/* Sanity check, cmd len will be recalculated later */
		if(csf_hdr_len < HAB_CSF_CMD_MIN_LEN ||
		   csf_hdr_len > HAB_CSF_CMD_MAX_LEN) {
			dbprintf("CSF cmd len %zu\n", *csf_len);
			goto err_out;
		}
		return &buf[csf_pos];
	}

err_out:
	return NULL;
}

/* Nothing advanced, just mmap file */
static int
mmap_file(char *file, size_t len, uint8_t **mem, size_t *size)
{
	int fd;
	uint8_t *buf;
	struct stat st;

	fd = -1;
	if (!file || !mem || !size) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	fd = open(file, O_RDONLY);
	if (-1 == fd) {
		dbprintf("Could not open file.\n");
		goto err_out;
	}
	if (!len) {
		/* Could be more flexible here in getting size.
		 * Code could probably work straight on nodes
		 * but may need lseek or similar.
		 */
		memset(&st, 0, sizeof(st));
		if (fstat(fd, &st) == -1) {
			dbprintf("No file size.\n");
			goto err_out;
		}
		len = st.st_size;
	}
	buf = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		dbprintf("Could not mmap file.\n");
		goto err_out;
	}

	if (fd >= 0) close(fd);
	*mem = buf;
	*size = len;
	return 1;

err_out:
	if (fd >= 0) close(fd);
	return 0;
}

/* Higher level function.
 * Calls mmap_file and then extracts
 * the csf pointer from it.
 * Places raw mmap pointers and the
 * extracted pointers in the habcsf struct.
 */
static int
read_csf_file(char *fname, habcsf_t *hcsf)
{
	uint8_t *buf;
	size_t len;

	if (!fname || !fname[0]) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	if (!hcsf) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	if (!mmap_file(fname, 0, &buf, &len)) {
		dbprintf("Could not mmap file.\n");
		goto err_out;
	}
	memset(hcsf, 0, sizeof(habcsf_t));
	hcsf->rawbuf = buf;
	hcsf->rawlen = len;
	hcsf->buf = extract_csf(buf, len, &hcsf->len);
	if (!hcsf->buf || !hcsf->len) {
		dbprintf("Could not extract csf.\n");
		goto err_out;
	}

	return 1;

err_out:
	return 0;
}

/* Calculate the hash.
 * Nothing fancy, takes a blob
 * and calculates a sha256 hash from it.
 * Allocated buffer needs to be freed by caller.
 */
static uint8_t *
calc_hash(uint8_t *buf, size_t buf_len, size_t *hashlen)
{
	uint8_t *hash_buf;
	unsigned int hash_buf_len;
	const EVP_MD *type;
	EVP_MD_CTX *ctx;

	ctx = NULL;
	hash_buf = NULL;
	if (!buf || !buf_len || !hashlen) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	if (!(hash_buf = (uint8_t *)malloc(EVP_MAX_MD_SIZE))) {
		dbprintf("Can't malloc digest storage for sha256.\n");
		goto err_out;
	}
	if (!(type = EVP_get_digestbyname("sha256"))) {
		dbprintf("Can't use digest sha256.\n");
		goto err_out;
	}
	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		dbprintf("Can't allocate md ctx.\n");
		goto err_out;
	}
	if (!EVP_DigestInit(ctx, type)) {
		dbprintf("Can't use digest sha256.\n");
		goto err_out;
	}
	if (!EVP_DigestUpdate(ctx, buf, buf_len)) {
		dbprintf("Can't use digest sha256.\n");
		goto err_out;
	}
	EVP_DigestFinal(ctx, hash_buf, &hash_buf_len);
	*hashlen = hash_buf_len;

	if (ctx) EVP_MD_CTX_free(ctx);
	return hash_buf;

err_out:
	if (ctx) EVP_MD_CTX_free(ctx);
	if (hash_buf) free(hash_buf);
	return NULL;
}

/* Used in conjunction with the srktable hash calculation.
 * Converts a string to an ascii string.
 * In this case the binary hash to ascii.
 */
static int
hash_to_sha_str(uint8_t *hash, size_t hashlen,
		char *buf, size_t buflen)
{
	size_t i;

	if (!hash || !buf) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	if (hashlen != SHA256_DIGEST_LENGTH ||
	    buflen < 2 * hashlen) {
		dbprintf("Not enough space for sha256 ascii string.\n");
		goto err_out;
	}
	for (i = 0; i < hashlen; i++) {
		sprintf(buf + i * 2, "%02x", hash[i]);
	}

	return 1;

err_out:
	return 0;
}

/* Used by the validation process.
 * The certs are DER encoded in the CSF.
 * Extract them and put them in a more
 * useful openssl x509 structure.
 */
static int
der2cert(X509 **cert, uint8_t *buf, size_t buflen)
{
	if (!cert || !buf || !buflen) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}

	*cert = d2i_X509(NULL, (const unsigned char **)&buf, buflen);
	if (!*cert) {
		dbprintf("Can't convert der cert to internal x509.\n");
		goto err_out;
	}

	return 1;

err_out:
	return 0;
}

/* Used by the validation process.
 * Converts a bignum to binary data.
 * This is used to convert the signer
 * RSA modulus to binary, so that we can
 * make sure to find the modulus in the
 * srktable. Ie, the signer cert, must
 * be in the srktable in fast auth.
 */
static uint8_t *
bn2buf(const BIGNUM *bn, size_t *bnlen)
{
	uint8_t *buf;

	if (!bn || !bnlen) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	*bnlen = BN_num_bytes(bn);
	buf = malloc(*bnlen);
	if (!buf) {
		dbprintf("Can't allocate bignum binary data buffer.\n");
		goto err_out;
	}
	BN_bn2bin(bn, buf);

	return buf;

err_out:
	return NULL;
}

/* Used by the validation process.
 * Sets the CMS contentinfo structure
 * from a bio flow.
 * This bio contains the signatures.
 * They are loaded into a CMS_ContentInfo structure
 * before we use it in CMS_verify.
 */
static CMS_ContentInfo *
set_content_info(BIO *in)
{
	CMS_ContentInfo *ret, *ci;

	ci = NULL;
	ret = NULL;
	if (!in) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	ci = CMS_ContentInfo_new();
	if (!ci) {
		dbprintf("Can't create contentinfo storage.\n");
		goto err_out;
	}
	ret = d2i_CMS_bio(in, &ci);
	if (!ret) {
		dbprintf("Can't convert der signature to internal cms.\n");
		goto err_out;
	}

	return ci;

err_out:
	if (ci) CMS_ContentInfo_free(ci);
	return NULL;
}

/* The big verification worker.
 * 1. Push the signer x509 cert into a certstack.
 * 2. Push the data to be validated into a BIO.
 * 3. Push the signature to be validated into a BIO.
 * 4. Create the cms_contentinfo from the signature bio
 *    using set_content_info.
 * 5. Do the validation.
 *
 * The openssl cmdline equivalent would be something like:
 * openssl cms -verify -inform der -certfile cert0.der \
 * -in sig0.bin -binary -content contentbin -noverify -out verified.txt
 *
 * Where: CMS is the signature format (cms) and we are verifying (-verify)
 * Cert is in der format (-inform der), using a cert. (-certfile).
 * Choose a signature to validate (-in).
 * All data is in binary format (-binary).
 * Choose a detached content (-content) to validate.
 * Don't validate certificate stack (-noverify).
 * And put the verified data somewhere (-out).
 *
 * This would done for the ivt+pbl and the csf commands.
 */
static int
verify_signature(X509 *cert, uint8_t *signature, size_t signature_len,
		 uint8_t *buf, size_t buf_len)
{
	BIO *in, *contents;
	CMS_ContentInfo *cms;
	STACK_OF(X509) *x509_certstack;

	in = NULL;
	contents = NULL;
	cms = NULL;
	x509_certstack = NULL;
	if (!cert || !signature || !signature_len) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	x509_certstack = sk_X509_new_null();
	if (!x509_certstack) {
		dbprintf("Can't create certstack storage.\n");
		goto err_out;
	}
	if (!sk_X509_push(x509_certstack, cert)) {
		dbprintf("Can't push cert on stack.\n");
		goto err_out;
	}
	contents = BIO_new_mem_buf(buf, buf_len);
	if (!contents) {
		dbprintf("Can't create BIO for content input.\n");
		goto err_out;
	}
	in = BIO_new_mem_buf(signature, signature_len);
	if (!in) {
		dbprintf("Can't create BIO for signature input.\n");
		goto err_out;
	}
	cms = set_content_info(in);
	if (!cms) {
		dbprintf("Can't set cms contentinfo from signature.\n");
		goto err_out;
	}
	/* We use DETACHED signatures (data and signature separate).
	 * Data is in binary format.
	 * And we don't verify the signer cert certificate stack.
	 * We don't have the signer cert CA on target, but we
	 * verify that the signer modulus is fused. So this should be ok.
	 */
	if (!CMS_verify(cms, x509_certstack, NULL,
			contents, NULL,
			CMS_DETACHED |
			CMS_BINARY |
			CMS_NO_SIGNER_CERT_VERIFY)) {
		dbprintf("Verification Failure\n");
		goto err_out;
	} else {
		dbprintf("Verification Success\n");
	}

	if (in) BIO_free(in);
	if (contents) BIO_free(contents);
	if (cms) CMS_ContentInfo_free(cms);
	if (x509_certstack) sk_X509_free(x509_certstack);

	return 1;

err_out:
	if (in) BIO_free(in);
	if (contents) BIO_free(contents);
	if (cms) CMS_ContentInfo_free(cms);
	if (x509_certstack) sk_X509_free(x509_certstack);

	return 0;
}

/* Check srkhash string supplied by user */
static int
check_input_srkhash(char *buf)
{
	size_t i;

	if (!buf || !buf[0]) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}

	/* Must be a sha256 hex string length */
	if (strlen(buf) != SHA256_HEX_STR_LEN) {
		dbprintf("srkhash strlen not equal to sha256 ascii string.\n");
		goto err_out;
	}
	/* Only hexadecimal digits */
	for (i = 0; i < SHA256_HEX_STR_LEN; i++) {
		if (!isxdigit(buf[i])) {
			dbprintf("srkhash contains invalid characters.\n");
			goto err_out;
		}
	}

	return 1;

err_out:
	return 0;
}

/* Compare incoming ascii of srktable hash with
 * ascii of calculated hash from CSF srktable.
 * Pick up the srktable from the srktablelist.
 * Return the matching srktable list entry if
 * successful, null otherwise.
 */
static listtype_t *
verify_srktable(char *srktable_in)
{
	listtype_t *esrkt;
	csf_srktable_key_t *key;
	char srktable_ascii[SHA256_HEX_STR_LEN + 1];
	uint8_t *hash, *srkeys_hash;
	size_t hashlen, curr, srkeys_hash_len;

	hash = NULL;
	srkeys_hash = NULL;
	if (!srktable_in || !srktable_in[0]) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	/* All keys hash.
	 * HABv4 is hash(hash(key1) + hash(keyn ))
	 * AHAB is just hash(keyblobs)
	 */
	srkeys_hash_len = EVP_MAX_MD_SIZE * 4;
	if (!(srkeys_hash = malloc(srkeys_hash_len))) {
		dbprintf("Could not allocate memory for srkeys hashes.\n");
		goto err_out;
	}
	memset(srkeys_hash, 0, srkeys_hash_len);
	/* Get first entry of srktablelist.
	 * This data must be stripped of the srktable header already.
	 * Reuse srkeys_hash_len to declare length of concatd. hashes.
	 */
	esrkt = list_entry((&srktablelist)->next, typeof(*esrkt), list);
	srkeys_hash_len = 0;
	for (curr = 0; curr < esrkt->buflen;) {
		key = (csf_srktable_key_t *)&(esrkt->buf[curr]);
		if (key->tag != HAB_KEY_PUBLIC) {
			dbprintf("srktable key is not declared public.\n");
			goto err_out;
		}
		/* Hashes are calculated including key headers */
		hash = calc_hash((uint8_t *)key, HAB_HDR_LEN(key), &hashlen);
		if (!hash) {
			dbprintf("Could not calculate a srkey hash.\n");
			goto err_out;
		}
		if (hashlen != SHA256_DIGEST_LENGTH) {
			dbprintf("Invalid srkey hash length.\n");
			goto err_out;
		}
		memcpy(&srkeys_hash[srkeys_hash_len], hash, hashlen);
		free(hash);
		hash = NULL;
		/* Increment input data offset and the srkeys hash data offset. */
		curr += HAB_HDR_LEN(key);
		srkeys_hash_len += hashlen;
	}
	/* Calc final table hash from key hashes. */
	hash = calc_hash(srkeys_hash, srkeys_hash_len, &hashlen);
	if (!hash) {
		dbprintf("Could not calculate srktable hash.\n");
		goto err_out;
	}
	memset(srktable_ascii, 0, sizeof(srktable_ascii));
	if (!hash_to_sha_str(hash, hashlen,
			     srktable_ascii, sizeof(srktable_ascii))) {
		dbprintf("Could not convert srktable bin to ascii.\n");
		goto err_out;
	}
	if (strncasecmp(srktable_ascii, srktable_in,
			SHA256_HEX_STR_LEN)) {
		dbprintf("srktable hash in file doesn't match input.\n");
		goto err_out;
	}
	dbprintf("SRKTable input SHA256 digest ascii: %s\n", srktable_in);
	dbprintf("SRKTable calcd SHA256 digest ascii: %s\n", srktable_ascii);

	if (hash) free(hash);
	if (srkeys_hash) free(srkeys_hash);
	return esrkt;

err_out:
	if (hash) free(hash);
	if (srkeys_hash) free(srkeys_hash);
	return NULL;
}

/* Take the cert and extract the RSA key modulus.
 * Now search for the modulus in the srktable.
 * The srktable is hashed and fused, so this is a
 * good check that the cert is valid.
 * Return the cert in x509 format when successful,
 * null otherwise.
 */
static X509 *
verify_cert_modulus_in_sktable(listtype_t *esrkt)
{
	listtype_t *ecert;
	X509 *cert;
	EVP_PKEY *pkey;
	const BIGNUM *n;
	const RSA *rsapkey;
	uint8_t *bnbuf;
	size_t bnbuf_len;

	cert = NULL;
	pkey = NULL;
	bnbuf = NULL;
	if (!esrkt) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	/* Get first (and should be only) entry of certlist */
	ecert = list_entry((&certlist)->next, typeof(*ecert), list);
	if (!der2cert(&cert, ecert->buf, ecert->buflen)) {
		dbprintf("Unable to decode der srk cert.\n");
		goto err_out;
	}
	if (!(pkey = X509_get_pubkey(cert))) {
		dbprintf("Could not extract pubkey from srk cert\n");
		goto err_out;
	}
	/* RSA key is get0, not to be freed */
	rsapkey = EVP_PKEY_get0_RSA(pkey);
	if (!rsapkey) {
		dbprintf("Could not extract pubkey from srk cert\n");
		goto err_out;
	}
	/* Bignums are get0, not to be freed */
	RSA_get0_key(rsapkey, &n, NULL, NULL);
	bnbuf = bn2buf(n, &bnbuf_len);
	if (!bnbuf) {
		dbprintf("Could not convert bignum to binary buffer\n");
		goto err_out;
	}
	/* Find signer pubkey modulus in srk table
	 * Yeah. Maybe not the best method in finding the modulus.
	 * Nor the most secure method.
	 */
	if (!memmem(esrkt->buf, esrkt->buflen,
		    bnbuf, bnbuf_len)) {
		dbprintf("Could not find cert rsa modulus in srktable\n");
		goto err_out;
	}

	if (pkey) EVP_PKEY_free(pkey);
	if (bnbuf) free(bnbuf);
	return cert;

err_out:
	if (cert) X509_free(cert);
	if (pkey) EVP_PKEY_free(pkey);
	if (bnbuf) free(bnbuf);
	return NULL;
}

/* Iterate over the signatures
 * We haven't figured out the ordering, of the data vs signature.
 * So just test all of them.
 * Returns 1 if one signature is valid against cert, 0 otherwise.
 */
static int
test_signatures(X509 *cert, uint8_t *buf, size_t buflen)
{
	listtype_t *esig;

	if (!cert || !buf || !buflen) {
		dbprintf("Invalid function parameters.\n");
		goto err_out;
	}
	dbprintf("Looping through the signatures, checking validity\n");
	list_for_each_entry(esig, &signaturelist, list) {
		if (verify_signature(cert, esig->buf, esig->buflen,
				     buf, buflen)) {
			goto out;
		}
	}

err_out:
	return 0;

out:
	return 1;
}

/* Input: Payload with hab csf and superrootkeyhash from fuses.
 * Checks superrootkey hash string.
 * Extracts CSF.
 * Parses/Validates CSF.
 * Make sure lists contain the right ammount of data
 * for the fast authentication process.
 * Hash the SRKtable and compare the ascii with incoming srk ascii.
 * Extract the cert and RSA modulus. Use the RSA modulus to
 * check if it exists in the srktable.
 * Use verify_signature to verify the IVT+PBL blob
 * and the CSF CMD blob.
 * All functions inside should return a zero comparable value
 * on failure, or positive otherwise.
 * But main returns 0, posix ok for success, 1 otherwise.
 */
int
main(int argc, char *argv[])
{
	char *binfile, *srkhashinput;
	listtype_t *esrkt;
	X509 *cert;
	habcsf_t hcsf;

	cert = NULL;
	memset(&hcsf, 0, sizeof(hcsf));
	fprintf(stderr, "-----------------------------------------------\n");
	fprintf(stderr, "i.MX8 CSF Validator\n");
	fprintf(stderr, "-----------------------------------------------\n");

	if (argc != 3) {
		fprintf(stderr, "Usage:\n");
		fprintf(stderr, "<BOOTLOADER> <SHA256 SRK-HASH ASCII>\n");
		fprintf(stderr, "[env: DEBUG_VALIDATION for debug]\n");
		goto err_out;
	}
	/* Set debug printouts if we find the env variable.
	 * We could use options instead.
	 */
	if (getenv("DEBUG_VALIDATION")) {
		debug = 1;
	}
	binfile = argv[1];
	srkhashinput = argv[2];
	if (!check_input_srkhash(srkhashinput)) {
		fprintf(stderr, "Invalid srk hash string.\n");
		goto err_out;
	}
	/* Read binary. Find the IVT and CSF pointers. */
	if (!read_csf_file(binfile, &hcsf)) {
		fprintf(stderr, "Error reading file. Could not find csf.\n");
		goto err_out;
	}
	/* Parse the CSF and stick data blocks in relevant spaces.
	 * This section does a lot of checks.
	 */
	if (!parse_csf(&hcsf)) {
		fprintf(stderr, "Error parsing csf data.\n");
		goto err_out;
	}
	/* We only allow one superrootkey table.
	 * Anything else doesn't make sense anyway.
	 */
	if (list_count(&srktablelist) != 1) {
		fprintf(stderr, "Multiple srk tables defined in csf.\n");
		goto err_out;
	}
	/* We only allow one cert, because we only use fast auth mode.
	 * In this mode we only have one cert in the CSF.
	 */
	if (list_count(&certlist) != 1) {
		fprintf(stderr, "Wrong number of certs defined.\n");
		goto err_out;
	}
	/* Make sure we have two signatures in the list.
	 * One for ivt+pbl. And one for the CSF.
	 */
	if (list_count(&signaturelist) != 2) {
		fprintf(stderr, "Wrong number of signatures defined in csf.\n");
		goto err_out;
	}
	/* Calculate the SRK table hash and compare it
	 * to the incoming ascii hex.
	 * The incoming string is the SRK hash from the
	 * fuse table, in ascii.
	 */
	if (!(esrkt = verify_srktable(srkhashinput))) {
		fprintf(stderr, "Mismatched srk table hashes.\n");
		goto err_out;
	}
	if (!(cert = verify_cert_modulus_in_sktable(esrkt))) {
		fprintf(stderr, "Couldn't find signer pub modulus in srktable.\n");
		goto err_out;
	}
	dbprintf("ivt+payload offset 0x%zx, len 0x%zx\n",
		 ivtandpayload_offset, ivtandpayload_len);
	dbprintf("csf cmds offset 0x%zx, len 0x%zx\n",
		 csfcmds_offset, csfcmds_len);

	if (!test_signatures(cert,
			     &hcsf.rawbuf[ivtandpayload_offset],
			     ivtandpayload_len) ||
	    !test_signatures(cert,
			     &hcsf.rawbuf[csfcmds_offset],
			     csfcmds_len)) {
		goto err_out;
	}

	fprintf(stdout, "Verification Success\n");
	if (cert) X509_free(cert);
	if (hcsf.rawbuf && hcsf.rawlen) munmap(hcsf.rawbuf, hcsf.rawlen);
	free_list(&srktablelist);
	free_list(&certlist);
	free_list(&signaturelist);
	return 0;

err_out:
	fprintf(stdout, "Verification Failure\n");
	if (cert) X509_free(cert);
	if (hcsf.rawbuf && hcsf.rawlen) munmap(hcsf.rawbuf, hcsf.rawlen);
	free_list(&srktablelist);
	free_list(&certlist);
	free_list(&signaturelist);
	return 1;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
