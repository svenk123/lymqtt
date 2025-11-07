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
#ifndef MQTT_CLIENT_H
#define MQTT_CLIENT_H

#include "mqtt_tls.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
  net_tls_t net;
  const char *client_id;
  int keepalive_s;
  int op_timeout_s;
  uint16_t next_msg_id;
  uint64_t last_io_ms;
  const char *bind_iface;
} mqtt_client_t;

int mqtt_client_connect(mqtt_client_t *c, const char *host, int port,
                        const char *sni, int use_tls, const char *psk_identity,
                        const uint8_t *psk_key, size_t psk_len, const char *ca,
                        const char *cert, const char *key,
                        const char *client_id, const char *username,
                        const char *password, int keepalive_s,
                        int op_timeout_s);

void mqtt_client_close(mqtt_client_t *c);

/* SUBSCRIBE (one topic) */
int mqtt_client_subscribe(mqtt_client_t *c, const char *topic, int qos);

/* PUBLISH (QoS 0/1) */
int mqtt_client_publish(mqtt_client_t *c, int qos, int retain,
                        const char *topic, const uint8_t *payload,
                        size_t payload_len);

/* Blocking receive of one MQTT frame (raw) with timeout in ms. */
int mqtt_client_recv_raw(mqtt_client_t *c, uint8_t *buf, size_t buflen,
                         int wait_ms);

/* Keepalive Ping if needed. */
int mqtt_client_maybe_ping(mqtt_client_t *c);

#endif
