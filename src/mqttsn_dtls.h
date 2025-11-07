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
#ifndef MQTTSN_DTLS_H
#define MQTTSN_DTLS_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* Abstract transport layer: Plain-UDP or DTLS over mbedTLS.
 * For caller it looks like a datagram socket with send/recv. */

typedef struct {
  int use_dtls;
  int sockfd;
  struct sockaddr_storage peer;
  socklen_t peerlen;

  /* mbedTLS structures (only allocated if use_dtls=1) */
  void *ssl;  /* mbedtls_ssl_context*   (opaque, to avoid header leak) */
  void *conf; /* mbedtls_ssl_config*    */
  void *ctr_drbg; /* mbedtls_ctr_drbg_context* */
  void *entropy;  /* mbedtls_entropy_context* */
  void *cookie;   /* mbedtls_ssl_cookie_ctx* */
  void *timer;    /* mbedtls_timing_delay_context* */

  /* PSK */
  const char *psk_identity;
  const uint8_t *psk_key;
  size_t psk_len;

  /* X.509 paths (optional) */
  const char *ca_path;
  const char *cert_path;
  const char *key_path;

  int timeout_ms; /* Handshake/IO total timeout per operation */
  const char *bind_iface;
} net_dtls_t;

/* Initialize UDP socket and optionally mbedTLS context. */
int net_dtls_init(net_dtls_t *n, const char *host, int port,
                  const char *sni_name, int use_dtls, const char *psk_identity,
                  const uint8_t *psk_key, size_t psk_len, const char *ca,
                  const char *cert, const char *key, int timeout_ms,
                  const char *bind_iface);

/* Send datagram (DTLS: over mbedtls_ssl_write, otherwise sendto). */
int net_dtls_send(net_dtls_t *n, const uint8_t *buf, size_t len);

/* Receive datagram with timeout (DTLS: ssl_read; Plain: recvfrom). Returns >=0
 * length, 0 on timeout, -1 on error. */
int net_dtls_recv(net_dtls_t *n, uint8_t *buf, size_t buflen, int wait_ms);

/* Release all resources. */
void net_dtls_free(net_dtls_t *n);

#endif
