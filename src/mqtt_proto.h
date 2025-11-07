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
#ifndef MQTT_PROTO_H
#define MQTT_PROTO_H

#include <stddef.h>
#include <stdint.h>

/* MQTT Control Packet Types */
enum {
  MQTT_PKT_CONNECT = 1,
  MQTT_PKT_CONNACK = 2,
  MQTT_PKT_PUBLISH = 3,
  MQTT_PKT_PUBACK = 4,
  MQTT_PKT_SUBSCRIBE = 8,
  MQTT_PKT_SUBACK = 9,
  MQTT_PKT_PINGREQ = 12,
  MQTT_PKT_PINGRESP = 13,
  MQTT_PKT_DISCONNECT = 14
};

int mqtt_encode_connect(uint8_t *buf, size_t buflen, const char *client_id,
                        int keepalive_s, int clean_start, const char *username,
                        const char *password);

int mqtt_decode_connack(const uint8_t *buf, size_t len, int *session_present,
                        int *rc);

int mqtt_encode_subscribe(uint8_t *buf, size_t buflen, uint16_t msg_id,
                          const char *topic, int qos);

int mqtt_decode_suback(const uint8_t *buf, size_t len, uint16_t *msg_id,
                       int *granted_qos);

int mqtt_encode_publish(uint8_t *buf, size_t buflen, int qos, int retain,
                        int dup, const char *topic, uint16_t msg_id,
                        const uint8_t *payload, size_t paylen, size_t *out_len);

int mqtt_encode_puback(uint8_t *buf, size_t buflen, uint16_t msg_id);

int mqtt_decode_publish_fixed(const uint8_t *buf, size_t len, int *qos,
                              int *retain, int *dup, size_t *remaining_len);

int mqtt_extract_topic_msgid(const uint8_t *buf, size_t len, char *topic,
                             size_t topic_cap, uint16_t *msg_id,
                             const uint8_t **payload, size_t *paylen);

int mqtt_encode_pingreq(uint8_t *buf, size_t buflen);
int mqtt_encode_disconnect(uint8_t *buf, size_t buflen);

#endif
