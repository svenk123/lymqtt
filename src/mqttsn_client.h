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
#ifndef MQTTSN_CLIENT_H
#define MQTTSN_CLIENT_H

#include "mqttsn_dtls.h"
#include <stddef.h>
#include <stdint.h>

/* MQTT-SN Client-Highlevel: Connection build, REGISTER, SUBSCRIBE, PUBLISH,
 * PUBACK, DISCONNECT. Simple Retry-/Timeout logic, QoS 0/1, QoS -1
 * (Fire&Forget). */

typedef struct {
  net_dtls_t net;
  const char *client_id;
  int keepalive_s;
  int op_timeout_s; /* for request/response */
  uint16_t next_msg_id;
  const char *bind_iface;
} mqttsn_client_t;

/* Initialize transport + Connect (CleanSession=1). */
int mqttsn_client_connect(mqttsn_client_t *c, const char *host, int port,
                          const char *sni_name, int use_dtls,
                          const char *psk_identity, const uint8_t *psk,
                          size_t psk_len, const char *ca, const char *cert,
                          const char *key, const char *client_id,
                          int keepalive_s, int timeout_s);

/* Clean DISCONNECT and free resources. */
void mqttsn_client_close(mqttsn_client_t *c);

/* Register topic-name → topic-id from broker. */
int mqttsn_client_register(mqttsn_client_t *c, const char *topic_name,
                           uint16_t *out_topic_id);

/* Subscribe per topic-name or topic-id. Returns final to use topic-id. */
int mqttsn_client_subscribe_name(mqttsn_client_t *c, const char *topic_name,
                                 int qos, uint16_t *out_topic_id);
int mqttsn_client_subscribe_id(mqttsn_client_t *c, uint16_t topic_id,
                               int id_type, int qos);

/* Publish. If QoS1 wait for PUBACK; QoS0 send only; QoS-1 (if broker allows)
 * fire&forget. */
int mqttsn_client_publish(mqttsn_client_t *c, int qos, int retain,
                          uint16_t topic_id, int id_type,
                          const uint8_t *payload, size_t payload_len);

/* Blocking receive for one datagram (raw) with global timeout. */
int mqttsn_client_recv(mqttsn_client_t *c, uint8_t *buf, size_t buflen,
                       int wait_ms);

#endif
