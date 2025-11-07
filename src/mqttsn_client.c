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
#include "mqttsn_client.h"
#include "mqttsn_common.h"
#include "util.h"
#include <string.h>
#include <unistd.h>

static uint16_t next_id(mqttsn_client_t *c) {
  if (++c->next_msg_id == 0)
    c->next_msg_id = 1;
  return c->next_msg_id;
}

int mqttsn_client_connect(mqttsn_client_t *c, const char *host, int port,
                          const char *sni_name, int use_dtls,
                          const char *psk_identity, const uint8_t *psk,
                          size_t psk_len, const char *ca, const char *cert,
                          const char *key, const char *client_id,
                          int keepalive_s, int timeout_s) {
  const char *iface = c->bind_iface;
  c->client_id = client_id;
  c->keepalive_s = keepalive_s;
  c->op_timeout_s = timeout_s > 0 ? timeout_s : 5;
  c->next_msg_id = 1;
  c->bind_iface = iface;

  log_info("client_connect: bind_iface=%s",
           c->bind_iface ? c->bind_iface : "(none)");
  if (net_dtls_init(&c->net, host, port, sni_name, use_dtls, psk_identity, psk,
                    psk_len, ca, cert, key, c->op_timeout_s,
                    c->bind_iface) != 0) {
    log_err("Transport-Init failed.");

    return -1;
  }

  /* CONNECT send, Connack expect */
  uint8_t pkt[512];
  int n = mqttsn_encode_connect(pkt, sizeof(pkt), client_id, keepalive_s, 1);
  if (n < 0) {
    log_err("CONNECT Encode failed.");
    
    return -1;
  }

  if (net_dtls_send(&c->net, pkt, n) <= 0) {
    log_err("CONNECT send failed.");
    return -1;
  }

  uint64_t t0 = now_ms();
  for (;;) {
    int r = net_dtls_recv(&c->net, pkt, sizeof(pkt), 1000);
    if (r == 0) {
      if (timed_out(t0, c->op_timeout_s * 1000)) {
        log_err("CONNACK Timeout");

        return -1;
      }

      continue;
    }

    if (r < 0) {
      log_err("CONNACK recv Fehler");
      return -1;
    }

    uint8_t rc = 0xff;
    if (mqttsn_decode_connack(pkt, r, &rc) > 0) {
      if (rc == MQTTSN_RC_ACCEPTED) {
        log_info("Connected (CONNACK=ACCEPTED)");

        return 0;
      }
      log_err("CONNACK RC=%u", rc);

      return -1;
    }

    /* Foreign packet? ignore */
  }
}

void mqttsn_client_close(mqttsn_client_t *c) {
  uint8_t pkt[8];
  int n = mqttsn_encode_disconnect(pkt, sizeof(pkt), 0);
  if (n > 0)
    (void)net_dtls_send(&c->net, pkt, n);

  net_dtls_free(&c->net);
}

int mqttsn_client_register(mqttsn_client_t *c, const char *topic_name,
                           uint16_t *out_topic_id) {
  uint8_t pkt[512];
  uint16_t id = next_id(c);
  int n = mqttsn_encode_register(pkt, sizeof(pkt), id, topic_name);
  if (n < 0)
    return -1;

  if (net_dtls_send(&c->net, pkt, n) <= 0)
    return -1;

  uint64_t t0 = now_ms();
  for (;;) {
    int r = net_dtls_recv(&c->net, pkt, sizeof(pkt), 1000);
    if (r == 0) {
      if (timed_out(t0, c->op_timeout_s * 1000))
        return -1;

      continue;
    }

    /* Error */
    if (r < 0)
      return -1;

    uint16_t topic_id, msg_id;
    uint8_t rc;
    if (mqttsn_decode_regack(pkt, r, &topic_id, &msg_id, &rc) > 0) {
      if (msg_id != id)
        continue;

      if (rc == MQTTSN_RC_ACCEPTED) {
        *out_topic_id = topic_id;

        /* Success */
        return 0;
      }
      log_err("REGACK RC=%u", rc);

      return -1;
    }
  }
}

int mqttsn_client_subscribe_name(mqttsn_client_t *c, const char *topic_name,
                                 int qos, uint16_t *out_topic_id) {
  uint8_t pkt[512];
  uint16_t id = next_id(c);
  int n =
      mqttsn_encode_subscribe_topicname(pkt, sizeof(pkt), id, qos, topic_name);
  if (n < 0)
    return -1;

  if (net_dtls_send(&c->net, pkt, n) <= 0)
    return -1;

  uint64_t t0 = now_ms();
  for (;;) {
    int r = net_dtls_recv(&c->net, pkt, sizeof(pkt), 1000);
    if (r == 0) {
      if (timed_out(t0, c->op_timeout_s * 1000))
        return -1;

      continue;
    }

    /* Error */
    if (r < 0)
      return -1;

    uint16_t topic_id, msg_id;
    uint8_t rc, rqos;
    if (mqttsn_decode_suback(pkt, r, &topic_id, &rqos, &msg_id, &rc) > 0) {
      if (msg_id != id)
        continue;

      if (rc == MQTTSN_RC_ACCEPTED) {
        if (out_topic_id)
          *out_topic_id = topic_id;

        return 0;
      }

      log_err("SUBACK RC=%u", rc);

      return -1;
    }
  }
}

int mqttsn_client_subscribe_id(mqttsn_client_t *c, uint16_t topic_id,
                               int id_type, int qos) {
  uint8_t pkt[64];
  uint16_t id = next_id(c);
  int n = mqttsn_encode_subscribe_topicid(pkt, sizeof(pkt), id, qos, topic_id,
                                          id_type);
  if (n < 0)
    return -1;

  if (net_dtls_send(&c->net, pkt, n) <= 0)
    return -1;

  uint64_t t0 = now_ms();
  for (;;) {
    int r = net_dtls_recv(&c->net, pkt, sizeof(pkt), 1000);
    if (r == 0) {
      if (timed_out(t0, c->op_timeout_s * 1000))
        return -1;

      continue;
    }

    /* Error */
    if (r < 0)
      return -1;

    uint16_t tid, msg_id;
    uint8_t rc, rqos;
    if (mqttsn_decode_suback(pkt, r, &tid, &rqos, &msg_id, &rc) > 0) {
      if (msg_id != id)
        continue;

      if (rc == MQTTSN_RC_ACCEPTED)
        return 0;

      log_err("SUBACK RC=%u", rc);

      return -1;
    }
  }
}

int mqttsn_client_publish(mqttsn_client_t *c, int qos, int retain,
                          uint16_t topic_id, int id_type,
                          const uint8_t *payload, size_t payload_len) {
  uint8_t pkt[1024];
  uint16_t id = (qos == 1) ? next_id(c) : 0;
  int n = mqttsn_encode_publish(pkt, sizeof(pkt), qos, retain, topic_id,
                                id_type, id, payload, payload_len);
  if (n < 0)
    return -1;

  if (net_dtls_send(&c->net, pkt, n) <= 0)
    return -1;

  if (qos != 1)
    return 0; /* QoS 0 or -1: done */

  /* Wait for PUBACK */
  uint64_t t0 = now_ms();
  for (;;) {
    int r = net_dtls_recv(&c->net, pkt, sizeof(pkt), 1000);
    if (r == 0) {
      if (timed_out(t0, c->op_timeout_s * 1000))
        return -2;

      continue;
    }

    /* Error */
    if (r < 0)
      return -1;
    uint16_t tid, mid;
    uint8_t rc;

    if (mqttsn_decode_puback(pkt, r, &tid, &mid, &rc) > 0) {
      if (mid != id)
        continue;

      if (rc == MQTTSN_RC_ACCEPTED)
        return 0;

      log_err("PUBACK RC=%u", rc);
      
      return -1;
    }
  }
}

int mqttsn_client_recv(mqttsn_client_t *c, uint8_t *buf, size_t buflen,
                       int wait_ms) {
  return net_dtls_recv(&c->net, buf, buflen, wait_ms);
}
