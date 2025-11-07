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
#include "mqttsn_dtls.h"
#include "util.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>  // fd_set, FD_ZERO, FD_SET, select()
#include <sys/time.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>

/* mbedTLS Forward declarations without public headers to leak */
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/timing.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

#include <mbedtls/debug.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl_ciphersuites.h>

extern int g_log_level;

#if !defined(MBEDTLS_GCM_C) || !defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) || !defined(MBEDTLS_SHA256_C)
#error "mbedTLS ohne GCM/PSK/SHA256 gebaut – TLS_PSK_WITH_AES_128_GCM_SHA256 nicht verfügbar."
#endif

/* UDP send/recv callbacks for mbedTLS DTLS */
static int udp_send(void *ctx, const unsigned char *buf, size_t len) {
    net_dtls_t *n = (net_dtls_t*)ctx;
    ssize_t r = sendto(n->sockfd, buf, len, 0, (struct sockaddr*)&n->peer, n->peerlen);
    if (r < 0)
        return MBEDTLS_ERR_NET_SEND_FAILED;

    return (int)r;
}

static int udp_recv(void *ctx, unsigned char *buf, size_t len) {
    net_dtls_t *n = (net_dtls_t*)ctx;

    for (;;) {
        struct timeval tv = { .tv_sec = n->timeout_ms/1000,
                              .tv_usec = (n->timeout_ms%1000)*1000 };
        fd_set fds; FD_ZERO(&fds); FD_SET(n->sockfd, &fds);
        int rv = select(n->sockfd+1, &fds, NULL, NULL, &tv);
        if (rv == 0)
            return MBEDTLS_ERR_SSL_TIMEOUT;

        if (rv < 0) {
            if (errno == EINTR)
                continue;

            return MBEDTLS_ERR_NET_RECV_FAILED;
        }

        ssize_t r = recvfrom(n->sockfd, buf, len, 0, NULL, NULL);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                return MBEDTLS_ERR_SSL_WANT_READ;

            return MBEDTLS_ERR_NET_RECV_FAILED;
        }

        return (int)r;
    }
}

/* Output the local source address after binding (without getnameinfo) */
static void log_sock_local(int fd) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getsockname(fd, (struct sockaddr*)&ss, &slen) != 0)
        return;

    char ip[INET6_ADDRSTRLEN] = {0};
    int ok = 0;

    if (ss.ss_family == AF_INET) {
        const struct sockaddr_in *sa = (const struct sockaddr_in*)&ss;
        ok = inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip)) != NULL;
    } else if (ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6*)&ss;
        ok = inet_ntop(AF_INET6, &sa6->sin6_addr, ip, sizeof(ip)) != NULL;  // <- sin6_addr!
    }

    if (ok) 
        log_info("Local src addr: %s", ip);
}

static int resolve_and_bind(net_dtls_t *n, const char *host, int port)
{
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    struct addrinfo hints = {0}, *res = NULL, *ai = NULL;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family   = AF_UNSPEC;

    int rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        return -1;
    }

    int sockfd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sockfd < 0)
            continue;

        /* bind to interface, if desired */
        if (n->bind_iface && net_bind_to_interface(sockfd, n->bind_iface, ai->ai_family) != 0) {
            close(sockfd);
            sockfd = -1;

            continue;
        }

        if (n->bind_iface)
            log_info("Bind to iface '%s' successfully.", n->bind_iface);
        log_sock_local(sockfd);

        /* We remember the peer address; UDP doesn't need connect() necessarily */
        memcpy(&n->peer, ai->ai_addr, ai->ai_addrlen);
        n->peerlen = (socklen_t)ai->ai_addrlen;
        n->sockfd = sockfd;

        break;
    }

    freeaddrinfo(res);

    if (sockfd < 0) {
        return -1;
    }

    return 0;
}

/* mbedTLS-Debug-Callback for --verbose>=2 (C, no Lambdas) */
static void mbedtls_dbg_cb(void *ctx, int level, const char *file, int line, const char *str) {
    (void)ctx;
    /* Level 1..4, we give everything through – Filter makes mbedtls_debug_set_threshold() */
    fprintf(stderr, "mbedtls[%d] %s:%d: %s", level, file, line, str);
}

static void log_suites(const int *suites, const char *tag){
    if (!suites) {
        log_info("%s: (null)", tag); 
        return;
    }
    
    int i = 0;
    for (const int *p = suites; *p != 0; ++p, ++i) {
        const char *name = mbedtls_ssl_get_ciphersuite_name(*p);
        log_info("%s[%d]: %s (%d)", tag, i, name ? name : "unknown", *p);
    }

    if (i == 0)
        log_err("%s: NO CIPHERSUITES (list empty)!", tag);
}

/* Set SNI: prefer --sni, then --host if no IP literal */
static int is_ip_literal(const char *h) {
    if (!h)
        return 0;

    for (const char *p = h; *p; ++p) {
        if (!( (*p >= '0' && *p <= '9') || *p=='.' || *p==':' ))
            return 0;
    }

    return 1; /* only digits/.: -> IP */
}

int net_dtls_init(net_dtls_t *n, const char *host, int port, const char *sni_name, int use_dtls,
                  const char *psk_identity, const uint8_t *psk_key, size_t psk_len,
                  const char *ca, const char *cert, const char *key,
                  int timeout_ms, const char *bind_iface) {
    memset(n, 0, sizeof(*n));
    n->use_dtls = use_dtls;
    n->timeout_ms = timeout_ms>0 ? timeout_ms*1000 : 5000;

    n->sockfd = -1;
    n->bind_iface = bind_iface;
    if (resolve_and_bind(n, host, port) != 0)
        return -1;

    log_info("net_dtls_init: requested iface=%s", bind_iface ? bind_iface : "(none)");

    if (!use_dtls)
        return 0;

    /* allocate mbedTLS structures */
    mbedtls_ssl_context *ssl = calloc(1, sizeof(*ssl));
    mbedtls_ssl_config *conf = calloc(1, sizeof(*conf));
    mbedtls_ctr_drbg_context *ctr = calloc(1, sizeof(*ctr));
    mbedtls_entropy_context *ent = calloc(1, sizeof(*ent));
    mbedtls_ssl_cookie_ctx *cookie = calloc(1, sizeof(*cookie));
    mbedtls_timing_delay_context *timer = calloc(1, sizeof(*timer));
    if (!ssl||!conf||!ctr||!ent||!cookie||!timer) {
        log_err("Out of memory."); 
        return -1; 
    }

    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_ctr_drbg_init(ctr);
    mbedtls_entropy_init(ent);
    mbedtls_ssl_cookie_init(cookie);

    const char *pers = "mqttsn-dtls";
    int ret = mbedtls_ctr_drbg_seed(ctr, mbedtls_entropy_func, ent, (const unsigned char*)pers, strlen(pers));
    if (ret != 0) { 
        log_err("ctr_drbg_seed: %d", ret); 
        goto fail;
    }

    if ((ret = mbedtls_ssl_config_defaults(conf,
        MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        log_err("ssl_config_defaults: %d", ret);
        goto fail;
    }

    /* Debug only when --verbose>=2 */
    if (g_log_level >= 2) {
        mbedtls_ssl_conf_dbg((mbedtls_ssl_config*)conf, mbedtls_dbg_cb, NULL);
        mbedtls_debug_set_threshold(4); /* 0-4 */
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr);
//    mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); /* DTLS 1.2 */
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    if (psk_identity && psk_key && psk_len > 0 && (!ca && !cert && !key)) {
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    ret = mbedtls_ssl_conf_psk(conf, psk_key, psk_len,
                               (const unsigned char*)psk_identity,
                               strlen(psk_identity));
    if (ret != 0) {
        log_err("conf_psk: %d", ret); 
        goto fail;
    }
#else
    log_err("mbedTLS without PSK support built – enable e.g. MBEDTLS_KEY_EXCHANGE_PSK_ENABLED.");
    ret = -1; 
    goto fail;
#endif
    } else if (ca || cert || key) {
        /* X.509 optional – simple validation (VERIFY_OPTIONAL) */
        static mbedtls_x509_crt cacert;
        static mbedtls_x509_crt clicert;
        static mbedtls_pk_context pkey;
        mbedtls_x509_crt_init(&cacert);
        mbedtls_x509_crt_init(&clicert);
        mbedtls_pk_init(&pkey);

        if (ca) {
            if ((ret = mbedtls_x509_crt_parse_file(&cacert, ca)) != 0) {
                log_err("x509 parse ca: %d", ret); 
                goto fail;
            }

            mbedtls_ssl_conf_ca_chain(conf, &cacert, NULL);
        }

        if (cert && key) {
            if ((ret = mbedtls_x509_crt_parse_file(&clicert, cert)) != 0) {
                log_err("x509 parse cert: %d", ret); 
                goto fail; 
            }

            if ((ret = mbedtls_pk_parse_keyfile(&pkey, key, NULL)) != 0) {
                log_err("x509 parse key: %d", ret);
                goto fail;
            }

            if ((ret = mbedtls_ssl_conf_own_cert(conf, &clicert, &pkey)) != 0) {
                log_err("conf_own_cert: %d", ret);
                goto fail;
            }
        }
    } else {
        log_info("DTLS without PSK/X.509 – this will usually fail (Broker requires Auth).");
    }

    if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0) {
        log_err("ssl_setup: %d", ret);
        goto fail;
    }

    mbedtls_ssl_set_timer_cb(ssl, timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
    mbedtls_ssl_set_bio(ssl, n, udp_send, udp_recv, NULL);

/* 1) SNI */
const char *sni_eff = (sni_name && *sni_name) ? sni_name
                    : (host && !is_ip_literal(host) ? host : NULL);

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
if (sni_eff) {
    int sret = mbedtls_ssl_set_hostname(ssl, sni_eff);  /* IMPORTANT: on 'ssl', not n->ssl */
    if (sret == 0) {
        if (g_log_level >= 1)
            log_info("SNI enabled: %s", sni_eff);
    } else {
        char err[128]; mbedtls_strerror(sret, err, sizeof err);
        log_info("SNI set_hostname(%s) ret=%d (%s) – ignore", sni_eff, sret, err);
    }
} else {
    if (g_log_level >= 1)
        log_info("SNI not set (CLI empty or Host is IP).");
}
#else
if (g_log_level >= 1)
    log_info("SNI not available: MBEDTLS_SSL_SERVER_NAME_INDICATION missing.");
#endif

/* 2) DTLS strictly on 1.2 (like your successful OpenSSL test) */
mbedtls_ssl_conf_min_version((mbedtls_ssl_config*)conf,
    MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);  /* DTLS 1.2 */

/* 3) MTU conservative */
mbedtls_ssl_set_mtu((mbedtls_ssl_context*)ssl, 1200);

/* 4) (Optional, but often helpful) Enable Extended Master Secret */
mbedtls_ssl_conf_extended_master_secret((mbedtls_ssl_config*)conf,
    MBEDTLS_SSL_EXTENDED_MS_ENABLED);

/* Optional: Ciphersuite-Liste restrict (only if Gateway wants GCM) */
#if 1
static const int cs_psk_gcm[] = {
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,
    /* MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384, */
    0
};
mbedtls_ssl_conf_ciphersuites(conf, cs_psk_gcm);

/* Optional: when verbose >=1, output the offered suites */
if (g_log_level >= 1) {
    log_suites(cs_psk_gcm, "Offered Suite");
}
#endif

    /* Client-HELLO/Handshake execution */
    uint64_t t0 = now_ms();
    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (timed_out(t0, n->timeout_ms)) {
                log_err("DTLS Handshake Timeout");
                ret = MBEDTLS_ERR_SSL_TIMEOUT;
                break;
            }

            continue;
        }

        char estr[256];
        mbedtls_strerror(ret, estr, sizeof(estr));
        log_err("ssl_handshake: %d (%s)", ret, estr);

        break;
    }
    if (ret != 0)
        goto fail;

    /* Success: output the negotiated suite & version (when verbose) */
    log_info("DTLS connected: %s, vers=%d.%d",
        mbedtls_ssl_get_ciphersuite(ssl),
        ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3 ? 1 : 1, /* DTLS: mapping internal, only show roughly */
        ssl->minor_ver);

    n->ssl = ssl; 
    n->conf = conf; 
    n->ctr_drbg = ctr; 
    n->entropy = ent; 
    n->cookie = cookie; 
    n->timer = timer;
    n->psk_identity = psk_identity; 
    n->psk_key = psk_key; 
    n->psk_len = psk_len;
    n->ca_path = ca; 
    n->cert_path = cert; 
    n->key_path = key;

    return 0;

fail:
    if (ssl) { 
        mbedtls_ssl_free(ssl); 
        free(ssl); 
    }

    if (conf) {
        mbedtls_ssl_config_free(conf);
        free(conf);
    }

    if (ctr) {
        mbedtls_ctr_drbg_free(ctr);
        free(ctr);
    }

    if (ent) {
        mbedtls_entropy_free(ent);
        free(ent);
    }

    if (cookie) {
        mbedtls_ssl_cookie_free(cookie);
        free(cookie);
    }

    if (timer) {
        free(timer);
    }

    close(n->sockfd);
    n->sockfd=-1;
    
    return -1;
}

int net_dtls_send(net_dtls_t *n, const uint8_t *buf, size_t len) {
    if (!n->use_dtls) {
        ssize_t r = sendto(n->sockfd, buf, len, 0, (struct sockaddr*)&n->peer, n->peerlen);
        return (r<0)?-1:(int)r;
    }

    int ret;
    uint64_t t0 = now_ms();
    while ((ret = mbedtls_ssl_write((mbedtls_ssl_context*)n->ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (timed_out(t0, n->timeout_ms))
                return 0;

            continue;
        }

        log_err("ssl_write: %d", ret);

        return -1;
    }

    /* Return the number of bytes written */
    return ret;
}

int net_dtls_recv(net_dtls_t *n, uint8_t *buf, size_t buflen, int wait_ms) {
    if (!n->use_dtls) {
        struct timeval tv = { .tv_sec = wait_ms/1000, .tv_usec = (wait_ms%1000)*1000 };
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(n->sockfd, &fds);
        int rc = select(n->sockfd+1, &fds, NULL, NULL, &tv);
        if (rc == 0)
            return 0; /* Timeout */

        if (rc < 0)
            return -1;

	    ssize_t r = recvfrom(n->sockfd, buf, buflen, 0, NULL, NULL);
        if (r < 0) {
            /* Error */
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                return 0; /* treat as timeout */

	        return -1;
	    }

        return (r<0)?-1:(int)r;
    }

    mbedtls_ssl_conf_read_timeout((mbedtls_ssl_config*)n->conf, (uint32_t)wait_ms);
    int ret = mbedtls_ssl_read((mbedtls_ssl_context*)n->ssl, buf, buflen);
    if (ret == MBEDTLS_ERR_SSL_TIMEOUT)
        return 0; /* Timeout */
    
    if (ret < 0) 
        return -1;

    /* Return the number of bytes read */
    return ret;
}

void net_dtls_free(net_dtls_t *n) {
    if (n->use_dtls && n->ssl) {
        mbedtls_ssl_close_notify((mbedtls_ssl_context*)n->ssl);
        mbedtls_ssl_free((mbedtls_ssl_context*)n->ssl);
        free(n->ssl); n->ssl=NULL;
    }

    if (n->conf){
        mbedtls_ssl_config_free((mbedtls_ssl_config*)n->conf);
        free(n->conf);
        n->conf=NULL;
    }

    if (n->ctr_drbg){
        mbedtls_ctr_drbg_free((mbedtls_ctr_drbg_context*)n->ctr_drbg);
        free(n->ctr_drbg);
        n->ctr_drbg=NULL;
    }

    if (n->entropy){
        mbedtls_entropy_free((mbedtls_entropy_context*)n->entropy);
        free(n->entropy);
        n->entropy=NULL;
    }

    if (n->cookie){
        mbedtls_ssl_cookie_free((mbedtls_ssl_cookie_ctx*)n->cookie);
        free(n->cookie);
        n->cookie=NULL;
    }

    if (n->timer){
        free(n->timer);
        n->timer=NULL;
    }

    if (n->sockfd>=0) {
        close(n->sockfd);
        n->sockfd=-1;
    }
}
