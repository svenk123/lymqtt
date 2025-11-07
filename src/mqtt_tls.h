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
#ifndef MQTT_TLS_H
#define MQTT_TLS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* Abstract transport layer: Plain-TCP or TLS (mbedTLS).
 * API is stream-oriented with read/write + timeout. */

typedef struct {
  int use_tls;
  int sockfd;
  struct sockaddr_storage peer;
  socklen_t peerlen;

  int timeout_ms; /* for read() */

  /* mbedTLS objects (only allocated if use_tls==1) */
  void *ssl;      /* mbedtls_ssl_context*      */
  void *conf;     /* mbedtls_ssl_config*       */
  void *ctr_drbg; /* mbedtls_ctr_drbg_context* */
  void *entropy;  /* mbedtls_entropy_context*  */
  void *cacert;   /* mbedtls_x509_crt*         */
  void *clicert;  /* mbedtls_x509_crt*         */
  void *pkey;     /* mbedtls_pk_context*       */
} net_tls_t;

/* Build TCP (connect), optional TLS Handshake.
 *  - host, port: target broker
 *  - sni: optional; if NULL → host
 *  - psk_identity/psk_key/psk_len: optional PSK
 *  - ca/cert/key: optional X.509 (PEM paths)
 *  - timeout_ms: operational timeout for read()
 * Return 0=OK, <0 error.
 */
int net_tls_connect(net_tls_t *n, const char *host, int port, const char *sni,
                    int use_tls, const char *psk_identity,
                    const uint8_t *psk_key, size_t psk_len, const char *ca,
                    const char *cert, const char *key, int timeout_ms,
                    const char *bind_iface);

/* Write (TLS: ssl_write; plain: send). */
int net_tls_send(net_tls_t *n, const uint8_t *buf, size_t len);

/* Read with timeout. Returns >=0 read bytes, 0 on timeout, -1 on error. */
int net_tls_recv(net_tls_t *n, uint8_t *buf, size_t buflen, int wait_ms);

/* Free resources. */
void net_tls_free(net_tls_t *n);

#endif
