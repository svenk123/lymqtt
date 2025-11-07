/* Minimal config for DTLS 1.2 Client with PSK (mbedTLS 2.16.x) */
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* System */
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

/* Protokoll / Core */
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_DTLS

/* RNG/Timing */
#define MBEDTLS_ENTROPY_C              /* <- MUST be present */
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_TIMING_C

/* Error texts (optional) */
#define MBEDTLS_ERROR_C
#define MBEDTLS_DEBUG_C

/* PSK only (no X.509/PK/ECC/DH) */
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define MBEDTLS_PSK_MAX_LEN 256

#define MBEDTLS_SSL_SERVER_NAME_INDICATION    /* Compile SNI extension */
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET    /* for mbedtls_ssl_conf_extended_master_secret() */

/* Crypto */
#define MBEDTLS_AES_C
#define MBEDTLS_CCM_C
#define MBEDTLS_GCM_C 
#define MBEDTLS_CIPHER_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
//#define MBEDTLS_SHA1_C        /* optional, if server requires it */
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED

/* Ciphersuite-Selection (adjust to Gateway) */
/*
#define MBEDTLS_SSL_CIPHERSUITES \
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8, \
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM,   \
    MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8, \
    MBEDTLS_TLS_PSK_WITH_AES_256_CCM, \
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256, \
    MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384
*/
#undef  MBEDTLS_SSL_CIPHERSUITES
#define MBEDTLS_SSL_CIPHERSUITES \
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256

/* Memory (optional) */
#define MBEDTLS_SSL_MAX_CONTENT_LEN 2048

/* For DTLS-Cookies */
#define MBEDTLS_SSL_COOKIE_C

/* For X.509 Certificate Support */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_OID_C

/* TLS */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
/* Optional TLS 1.3 – if your mbedTLS version supports it: */
/* #define MBEDTLS_SSL_PROTO_TLS1_3 */

#define MBEDTLS_SSL_SRV_NAME_INDICATION
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED

/* For PK (Private key etc.) */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_BIGNUM_C   /* needed for PK (RSA/ECC) */
#define MBEDTLS_MD_C

/* Recommended ciphers */
//#define MBEDTLS_CHACHAPOLY_C
//#define MBEDTLS_ARC4_C /* not used, but keep disabled by default */

/* Memory / platform */
#define MBEDTLS_PLATFORM_C

/* ECDSA prerequisites */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDSA_C
/* at least one curve active */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
/* often used: */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C

/* Core crypto */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C

/* ECC */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED

/* X.509 / PK */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C

/* TLS Client */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_SRV_NAME_INDICATION

/* PSK in TLS (falls genutzt) */
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED

/* Disable unused stuff to keep it small */
#undef MBEDTLS_NET_C            /* we use send/recv directly over POSIX */
#define MBEDTLS_TIMING_C        /* for TLS 1.3 – optional */

/* For RSA-Key (if you use PEM/DER RSA) */
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15

/* PEM-/Base64-Parsing for files (crt/key mostly PEM) */
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C

/* File-IO for *_parse_file() */
#define MBEDTLS_FS_IO

/* Ensure that nothing unwanted is active */
#undef MBEDTLS_CTR_DRBG_USE_128_BIT_KEY
#undef MBEDTLS_TEST_NULL_ENTROPY
#undef MBEDTLS_NO_PLATFORM_ENTROPY
//#undef MBEDTLS_RSA_C
//#undef MBEDTLS_PKCS1_V15
//#undef MBEDTLS_X509_USE_C
//#undef MBEDTLS_X509_CRT_PARSE_C
//#undef MBEDTLS_PK_C
//#undef MBEDTLS_PK_PARSE_C
//#undef MBEDTLS_ASN1_PARSE_C
//#undef MBEDTLS_BIGNUM_C
//#undef MBEDTLS_ECP_C
//#undef MBEDTLS_ECDH_C
//#undef MBEDTLS_ECDSA_C
//#undef MBEDTLS_DHM_
//#undef MBEDTLS_GCM_C

#include "mbedtls/check_config.h"
#endif /* MBEDTLS_CONFIG_H */
