/*****************************************************************************
 *
 * Copyright (c) 2025 Sven Kreiensen
 * All rights reserved.
 *
 * You can use this software under the terms of the MIT license
 * (see LICENSE.md).
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 *****************************************************************************/
#include "mqtt_tls.h"
#include "util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

/* mbedTLS Forward declarations */
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ticket.h>
#include <mbedtls/x509_crt.h>
#if defined(MBEDTLS_PSA_CRYPTO_C)
#include <psa/crypto.h>
#endif

static void tls_dbg(void *ctx, int level, const char *file, int line,
                    const char *str) {
  (void)ctx;
  log_dbg("[mbedTLS:%d] %s:%d: %s", level, file, line, str);
}

static void log_mbedtls_err(const char *where, int rc) {
  char buf[256];
  mbedtls_strerror(rc, buf, sizeof(buf));
  log_err("%s: rc=%d (0x%04x) %s", where, rc, (unsigned)(-rc), buf);
}

static void log_ssl_alert(mbedtls_ssl_context *ssl, const char *where) {
  if (!ssl)
    return;
  
  /* In mbedTLS 3.x, alert information might not be directly accessible.
   * The debug callback should provide detailed information when verbose >= 2.
   * Check certificate verification result which is often the cause of fatal alerts. */
  
  /* Check certificate verification result */
  uint32_t flags = mbedtls_ssl_get_verify_result(ssl);
  if (flags != 0) {
    log_err("%s: Certificate verification failed (flags: 0x%08x)", where, flags);
    if (flags & MBEDTLS_X509_BADCERT_EXPIRED)
      log_err("  - Certificate has expired");
    if (flags & MBEDTLS_X509_BADCERT_FUTURE)
      log_err("  - Certificate is not yet valid");
    if (flags & MBEDTLS_X509_BADCERT_REVOKED)
      log_err("  - Certificate has been revoked");
    if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)
      log_err("  - Certificate CN mismatch (check SNI)");
    if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
      log_err("  - Certificate is not trusted (check CA certificate)");
    if (flags & MBEDTLS_X509_BADCRL_NOT_TRUSTED)
      log_err("  - CRL is not trusted");
    if (flags & MBEDTLS_X509_BADCRL_EXPIRED)
      log_err("  - CRL has expired");
    if (flags & MBEDTLS_X509_BADCERT_MISSING)
      log_err("  - Certificate is missing");
    if (flags & MBEDTLS_X509_BADCERT_SKIP_VERIFY)
      log_err("  - Certificate verification was skipped");
    if (flags & MBEDTLS_X509_BADCERT_OTHER)
      log_err("  - Other certificate error");
  } else {
    log_err("%s: No certificate verification errors detected", where);
    log_err("  Common causes of fatal alerts:");
    log_err("  - Incompatible TLS version (server might require TLS 1.2 only)");
    log_err("  - No matching ciphersuite");
    log_err("  - Server requires client certificate");
    log_err("  - SNI mismatch");
    log_err("  - Use --verbose flag (>=2) for detailed mbedTLS debug output");
  }
}

/* Own BIO callbacks for mbedTLS, if MBEDTLS_NET_C is not used */
static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
  int fd = (int)(intptr_t)ctx;
  ssize_t r;

  do {
    r = send(fd, buf, len, MSG_NOSIGNAL);
  } while (r < 0 && errno == EINTR);

  if (r < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return MBEDTLS_ERR_SSL_WANT_WRITE;

    return -1;
  }

  return (int)r;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
  int fd = (int)(intptr_t)ctx;
  ssize_t r;

  do {
    r = recv(fd, buf, len, 0);
  } while (r < 0 && errno == EINTR);

  if (r < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return MBEDTLS_ERR_SSL_WANT_READ;

    return -1;
  }
  if (r == 0) {
    /* Peer closed - mbedTLS expects <0 for error/EOF */
    return -1;
  }

  return (int)r;
}

/* internal helper */
static int tcp_connect_with_timeout(const char *host, int port,
                                    const char *bind_iface,
                                    struct sockaddr_storage *out,
                                    socklen_t *outlen, int *outfd) {
  char portstr[16];
  snprintf(portstr, sizeof(portstr), "%d", port);
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res = NULL;
  int r = getaddrinfo(host, portstr, &hints, &res);
  if (r != 0) {
    log_err("getaddrinfo: %s", gai_strerror(r));

    return -1;
  }

  int fd = -1;
  struct addrinfo *ai;
  for (ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0)
      continue;

    if (bind_iface &&
        net_bind_to_interface(fd, bind_iface, ai->ai_family) != 0) {
      close(fd);
      fd = -1;

      continue;
    }

    if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
      memcpy(out, ai->ai_addr, ai->ai_addrlen);
      *outlen = (socklen_t)ai->ai_addrlen;
      freeaddrinfo(res);
      *outfd = fd;

      return 0;
    }

    close(fd);
    fd = -1;
  }

  freeaddrinfo(res);
  log_err("TCP connect() failed.");

  return -1;
}

static int tls_seed(void *entropy, void *ctr_drbg) {
  const char *pers = "mqtt_tls";
  int rc = mbedtls_ctr_drbg_seed((mbedtls_ctr_drbg_context *)ctr_drbg,
                                 mbedtls_entropy_func,
                                 (mbedtls_entropy_context *)entropy,
                                 (const unsigned char *)pers, strlen(pers));
  return rc == 0 ? 0 : -1;
}

int net_tls_connect(net_tls_t *n, const char *host, int port, const char *sni,
                    int use_tls, const char *psk_identity,
                    const uint8_t *psk_key, size_t psk_len, const char *ca,
                    const char *cert, const char *key, int timeout_ms,
                    const char *bind_iface) {
  memset(n, 0, sizeof(*n));
  n->use_tls = use_tls ? 1 : 0;
  n->timeout_ms = timeout_ms > 0 ? timeout_ms * 1000 : 10000;

  if (tcp_connect_with_timeout(host, port, bind_iface, &n->peer, &n->peerlen,
                               &n->sockfd) != 0) {
    log_err("TCP connect() failed.");
    return -1;
  }

  if (!n->use_tls)
    return 0;

  /* TLS init */
  mbedtls_entropy_context *entropy = calloc(1, sizeof(*entropy));
  mbedtls_ctr_drbg_context *ctr = calloc(1, sizeof(*ctr));
  mbedtls_ssl_config *conf = calloc(1, sizeof(*conf));
  mbedtls_ssl_context *ssl = calloc(1, sizeof(*ssl));
  mbedtls_x509_crt *cacert = NULL, *clicert = NULL;
  mbedtls_pk_context *pkey = NULL;

  if (!entropy || !ctr || !conf || !ssl) {
    log_err("Out of memory.");
    return -1;
  }

  mbedtls_entropy_init(entropy);
  mbedtls_ctr_drbg_init(ctr);
  mbedtls_ssl_config_init(conf);
  mbedtls_debug_set_threshold(4);
  mbedtls_ssl_conf_dbg(conf, tls_dbg, NULL);  /* Debug-Callback registrieren */
  mbedtls_ssl_init(ssl);

  if (tls_seed(entropy, ctr) != 0) {
    log_err("CTR_DRBG Seed failed.");
    return -1;
  }

#if defined(MBEDTLS_PSA_CRYPTO_C)
  /* TLS 1.3 requires PSA Crypto to be initialized */
  if (psa_crypto_init() != PSA_SUCCESS) {
    log_err("PSA Crypto initialization failed.");
    return -1;
  }
#endif

  if (mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT,
                                  MBEDTLS_SSL_TRANSPORT_STREAM,
                                  MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    log_err("ssl_config_defaults failed.");
    return -1;
  }

  /* ---------------------------------------------------------
   * Explicitly set allowed ciphersuites for TLS 1.2
   * Note: TLS 1.3 ciphersuites are automatically negotiated in mbedTLS 3.x
   *       and don't need to be specified here. This list only applies to TLS 1.2.
   * --------------------------------------------------------- */
  static const int cs[] = {
      /* TLS 1.3 Ciphersuites (wenn TLS 1.3 aktiviert ist) */
      MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
      MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
      /* TLS 1.2 Ciphersuites with AES-256 (for servers that prefer AES-256) */
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      /* TLS 1.2 Ciphersuites with AES-128 (fallback) */
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      /* PSK ciphersuites removed - using certificate-based authentication only */
      0};
  mbedtls_ssl_conf_ciphersuites(conf, cs);

  /* Set TLS version range: Allow both TLS 1.2 and TLS 1.3
   * TLS 1.2 = MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3
   * TLS 1.3 = MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4
   * This ensures TLS 1.2 can be used as fallback if server doesn't support TLS 1.3
   */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
  mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); /* TLS 1.2 minimum */
  mbedtls_ssl_conf_max_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4); /* TLS 1.3 maximum */
  
  /* Configure TLS 1.3 key exchange mode: Only ephemeral (no PSK)
   * This removes PSK-related extensions from the Client Hello
   */
  mbedtls_ssl_conf_tls13_key_exchange_modes(conf, MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
#else
  /* Only TLS 1.2 available */
  mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); /* TLS 1.2 */
  mbedtls_ssl_conf_max_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); /* TLS 1.2 */
#endif

  mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr);

  /* PSK is disabled - using certificate-based authentication only */
  if (psk_identity && psk_key && psk_len > 0) {
    log_err("PSK authentication is disabled. Please use certificate-based authentication (--ca, --cert, --key).");
    return -1;
  }

  /* CA/X.509? */
  if (ca) {
    cacert = calloc(1, sizeof(*cacert));
    mbedtls_x509_crt_init(cacert);
    if (mbedtls_x509_crt_parse_file(cacert, ca) != 0) {
      log_err("CA parse failed.");
      return -1;
    }

    mbedtls_ssl_conf_ca_chain(conf, cacert, NULL);
  }
  if (cert && key) {
    clicert = calloc(1, sizeof(*clicert));
    pkey = calloc(1, sizeof(*pkey));
    mbedtls_x509_crt_init(clicert);
    mbedtls_pk_init(pkey);
    if (mbedtls_x509_crt_parse_file(clicert, cert) != 0) {
      log_err("Client certificate parse failed.");

      return -1;
    }

    if (mbedtls_pk_parse_keyfile(pkey, key, "", mbedtls_ctr_drbg_random, ctr) != 0) {
      log_err("Private Key parse failed.");
      return -1;
    }
        
    if (mbedtls_ssl_conf_own_cert(conf, clicert, pkey) != 0) {
      log_err("own_cert failed.");
      return -1;
    }
  }

  if (mbedtls_ssl_setup(ssl, conf) != 0) {
    log_err("ssl_setup failed.");
    return -1;
  }

  const char *servername = (sni && *sni) ? sni : host;
  if (mbedtls_ssl_set_hostname(ssl, servername) != 0) {
    log_err("set_hostname failed.");
    return -1;
  }

  //    mbedtls_ssl_set_bio(ssl, (void*)(intptr_t)n->sockfd, mbedtls_net_send,
  //    mbedtls_net_recv, NULL);
  mbedtls_ssl_set_bio(ssl, (void *)(intptr_t)n->sockfd, bio_send, bio_recv,
                      NULL);

  int rc;
  while ((rc = mbedtls_ssl_handshake(ssl)) != 0) {
    if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
      log_mbedtls_err("TLS Handshake", rc);
      
      /* Get detailed alert information if available */
      if (rc == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE || 
          rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        log_ssl_alert(ssl, "TLS Handshake");
      }
      
      /* Log connection details for debugging */
      log_err("Connection details: Host=%s, Port=%d, SNI=%s", 
              host, port, servername ? servername : "(none)");
      if (ca) log_err("  CA certificate: %s", ca);
      if (cert) log_err("  Client certificate: %s", cert);
      
      return -1;
    }
  }
  
  /* After successful handshake, verify certificate and log connection info */
  uint32_t flags = mbedtls_ssl_get_verify_result(ssl);
  if (flags != 0) {
    log_err("Certificate verification warnings (flags: 0x%08x)", flags);
    if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)
      log_err("  - CN mismatch (SNI: %s)", servername ? servername : "(none)");
  }
  
  /* Log successful connection details */
  if (g_log_level >= 1) {
    const char *version = mbedtls_ssl_get_version(ssl);
    const char *ciphersuite = mbedtls_ssl_get_ciphersuite(ssl);
    log_info("TLS connected: %s, version=%s", 
             ciphersuite ? ciphersuite : "unknown",
             version ? version : "unknown");
  }

  n->ssl = ssl;
  n->conf = conf;
  n->ctr_drbg = ctr;
  n->entropy = entropy;
  n->cacert = cacert;
  n->clicert = clicert;
  n->pkey = pkey;

  return 0;
}

int net_tls_send(net_tls_t *n, const uint8_t *buf, size_t len) {
  if (!n->use_tls) {
    ssize_t r = send(n->sockfd, buf, len, 0);
    return (r < 0) ? -1 : (int)r;
  }

  /* Write to the socket */
  int off = 0;
  while (off < (int)len) {
    int r = mbedtls_ssl_write((mbedtls_ssl_context *)n->ssl, buf + off,
                              (int)(len - off));
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;

    if (r <= 0)
      return -1;

    off += r;
  }

  return off;
}

int net_tls_recv(net_tls_t *n, uint8_t *buf, size_t buflen, int wait_ms) {
  struct timeval tv = {.tv_sec = wait_ms / 1000,
                       .tv_usec = (wait_ms % 1000) * 1000};
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(n->sockfd, &fds);
  int rv = select(n->sockfd + 1, &fds, NULL, NULL, &tv);
  if (rv == 0)
    return 0; /* Timeout */

  if (rv < 0)
    return -1;

  if (!n->use_tls) {
    ssize_t r = recv(n->sockfd, buf, buflen, 0);
    if (r < 0)
      return -1;

    if (r == 0)
      return -1; /* EOF */

    /* Return the number of bytes read */
    return (int)r;
  } else {
    int r = mbedtls_ssl_read((mbedtls_ssl_context *)n->ssl, buf, buflen);
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
      return 0;

    if (r <= 0)
      return -1;

    /* Return the number of bytes read */
    return r;
  }
}

void net_tls_free(net_tls_t *n) {
  if (n->use_tls && n->ssl) {
    mbedtls_ssl_close_notify((mbedtls_ssl_context *)n->ssl);
  }
  if (n->sockfd > 0)
    close(n->sockfd);
  /* free TLS objects */
  if (n->ssl) {
    mbedtls_ssl_free((mbedtls_ssl_context *)n->ssl);
    free(n->ssl);
  }

  if (n->conf) {
    mbedtls_ssl_config_free((mbedtls_ssl_config *)n->conf);
    free(n->conf);
  }

  if (n->clicert) {
    mbedtls_x509_crt_free((mbedtls_x509_crt *)n->clicert);
    free(n->clicert);
  }

  if (n->cacert) {
    mbedtls_x509_crt_free((mbedtls_x509_crt *)n->cacert);
    free(n->cacert);
  }

  if (n->pkey) {
    mbedtls_pk_free((mbedtls_pk_context *)n->pkey);
    free(n->pkey);

  }
  if (n->ctr_drbg) {
    mbedtls_ctr_drbg_free((mbedtls_ctr_drbg_context *)n->ctr_drbg);
    free(n->ctr_drbg);
  }

  if (n->entropy) {
    mbedtls_entropy_free((mbedtls_entropy_context *)n->entropy);
    free(n->entropy);
  }
  
  memset(n, 0, sizeof(*n));
}
