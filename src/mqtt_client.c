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
#include "mqtt_client.h"
#include "mqtt_proto.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

static uint16_t next_id(mqtt_client_t *c) {
  if (++c->next_msg_id == 0)
    c->next_msg_id = 1;

  return c->next_msg_id;
}

int mqtt_client_connect(mqtt_client_t *c, const char *host, int port,
                        const char *sni, int use_tls, const char *psk_identity,
                        const uint8_t *psk_key, size_t psk_len, const char *ca,
                        const char *cert, const char *key,
                        const char *client_id, const char *username,
                        const char *password, int keepalive_s,
                        int op_timeout_s) {
  c->client_id = client_id;
  c->keepalive_s = keepalive_s > 0 ? keepalive_s : 60;
  c->op_timeout_s = op_timeout_s > 0 ? op_timeout_s : 10;
  c->next_msg_id = 1;

  if (net_tls_connect(&c->net, host, port, sni, use_tls, psk_identity, psk_key,
                      psk_len, ca, cert, key, c->op_timeout_s,
                      c->bind_iface) != 0) {
    return -1;
  }

  /* CONNECT */
  uint8_t pkt[1024];
  int n = mqtt_encode_connect(pkt, sizeof(pkt), client_id, c->keepalive_s, 1,
                              username, password);
  if (n < 0) {
    log_err("CONNECT encode failed");

    return -1;
  }

  if (net_tls_send(&c->net, pkt, n) != n)
    return -1;

  /* CONNACK */
  uint8_t rx[256];
  int r = mqtt_client_recv_raw(c, rx, sizeof(rx), c->op_timeout_s * 1000);

  if (r <= 0)
    return -1;

  int sp = 0, rc = 0;
  if (mqtt_decode_connack(rx, r, &sp, &rc) != 0 || rc != 0) {
    log_err("CONNACK error rc=%d", rc);
    return -1;
  }

  c->last_io_ms = now_ms();

  log_info("CONNECT OK");
  return 0;
}

void mqtt_client_close(mqtt_client_t *c) {
  if (!c)
    return;

  uint8_t disc[2];
  int n = mqtt_encode_disconnect(disc, sizeof(disc));

  if (n > 0)
    net_tls_send(&c->net, disc, n);

  net_tls_free(&c->net);
  memset(c, 0, sizeof(*c));

  log_info("DISCONNECT OK");
}

int mqtt_client_subscribe(mqtt_client_t *c, const char *topic, int qos) {
  uint8_t pkt[512];
  uint16_t mid = next_id(c);
  int n = mqtt_encode_subscribe(pkt, sizeof(pkt), mid, topic, qos);

  if (n < 0)
    return -1;

  if (net_tls_send(&c->net, pkt, n) != n)
    return -1;

  uint64_t start = now_ms();

  while (!timed_out(start, c->op_timeout_s * 1000)) {
    uint8_t rx[256];
    int r = mqtt_client_recv_raw(c, rx, sizeof(rx), 500);

    if (r <= 0)
      continue;

    if ((rx[0] >> 4) == MQTT_PKT_SUBACK) {
      uint16_t m;
      int gq;

      if (mqtt_decode_suback(rx, r, &m, &gq) == 0 && m == mid && gq != 0x80) {
        c->last_io_ms = now_ms();
        return 0;
      }

      return -1;
    }
    /* Ignore PINGRESP etc. */
  }

  log_err("SUBACK timeout");
  return -1;
}

int mqtt_client_publish(mqtt_client_t *c, int qos, int retain,
                        const char *topic, const uint8_t *payload,
                        size_t payload_len) {
  uint8_t pkt[2048];
  size_t plen = 0;
  uint16_t mid = qos > 0 ? next_id(c) : 0;

  if (mqtt_encode_publish(pkt, sizeof(pkt), qos, retain, 0, topic, mid, payload,
                          payload_len, &plen) != 0)
    return -1;

  if (net_tls_send(&c->net, pkt, (int)plen) != (int)plen)
    return -1;

  if (qos == 0) {
    c->last_io_ms = now_ms();

    return 0;
  }

  /* QoS1 -> wait for PUBACK */
  uint64_t start = now_ms();

  while (!timed_out(start, c->op_timeout_s * 1000)) {
    uint8_t rx[128];
    int r = mqtt_client_recv_raw(c, rx, sizeof(rx), 500);

    if (r <= 0)
      continue;

    if ((rx[0] >> 4) == MQTT_PKT_PUBACK && r >= 4) {
      uint16_t m = ((uint16_t)rx[2] << 8) | rx[3];

      if (m == mid) {
        c->last_io_ms = now_ms();

        return 0;
      }
    }
  }

  log_err("PUBACK timeout");
  return -1;
}

int mqtt_client_recv_raw(mqtt_client_t *c, uint8_t *buf, size_t buflen,
                         int wait_ms) {
  int r = net_tls_recv(&c->net, buf, buflen, wait_ms);

  return r;
}

int mqtt_client_maybe_ping(mqtt_client_t *c) {
  if (c->keepalive_s <= 0)
    return 0;

  uint64_t n = now_ms();

  if (n - c->last_io_ms < (uint64_t)c->keepalive_s * 1000 * 9 / 10)
    return 0;

  uint8_t ping[2];
  int L = mqtt_encode_pingreq(ping, sizeof(ping));

  if (L < 0)
    return -1;

  if (net_tls_send(&c->net, ping, L) != L)
    return -1;

  /* PINGRESP optional wait */
  uint8_t rx[8];
  (void)net_tls_recv(&c->net, rx, sizeof(rx), 1000);
  c->last_io_ms = now_ms();

  log_info("PINGRESP OK");
  return 0;
}
