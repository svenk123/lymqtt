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
#ifndef MQTTSN_COMMON_H
#define MQTTSN_COMMON_H

#include <stddef.h>
#include <stdint.h>

/* Minimal MQTT-SN v1.2 Subset.
 * Only the fields we need. Encoding is strictly limited and defensive.
 */

/* MQTT-SN control packet types */
enum {
  MQTTSN_ADVERTISE = 0x00,
  MQTTSN_SEARCHGW = 0x01,
  MQTTSN_GWINFO = 0x02,
  MQTTSN_CONNECT = 0x04,
  MQTTSN_CONNACK = 0x05,
  MQTTSN_WILLTOPICREQ = 0x06,
  MQTTSN_WILLTOPIC = 0x07,
  MQTTSN_WILLMSGREQ = 0x08,
  MQTTSN_WILLMSG = 0x09,
  MQTTSN_REGISTER = 0x0A,
  MQTTSN_REGACK = 0x0B,
  MQTTSN_PUBLISH = 0x0C,
  MQTTSN_PUBACK = 0x0D,
  MQTTSN_PUBCOMP = 0x0E,
  MQTTSN_PUBREC = 0x0F,
  MQTTSN_PUBREL = 0x10,
  MQTTSN_SUBSCRIBE = 0x12,
  MQTTSN_SUBACK = 0x13,
  MQTTSN_UNSUBSCRIBE = 0x14,
  MQTTSN_UNSUBACK = 0x15,
  MQTTSN_PINGREQ = 0x16,
  MQTTSN_PINGRESP = 0x17,
  MQTTSN_DISCONNECT = 0x18
};

/* Return Codes */
enum {
  MQTTSN_RC_ACCEPTED = 0x00,
  MQTTSN_RC_REJ_CONG = 0x01,
  MQTTSN_RC_REJ_INV_TOPIC_ID = 0x02,
  MQTTSN_RC_REJ_NOT_SUPPORTED = 0x03
};

/* Flags */
#define MQTTSN_FLAG_DUP (1 << 7)
#define MQTTSN_FLAG_QOS1 (1 << 5)
#define MQTTSN_FLAG_QOS0 (0 << 5)
#define MQTTSN_FLAG_QOSM1 (3 << 5)
#define MQTTSN_FLAG_RETAIN (1 << 4)
#define MQTTSN_FLAG_WILL (1 << 3)
#define MQTTSN_FLAG_CLEAN (1 << 2)
#define MQTTSN_FLAG_TOPIC_ID_TYPE_NORMAL 0x00
#define MQTTSN_FLAG_TOPIC_ID_TYPE_PREDEF 0x01
#define MQTTSN_FLAG_TOPIC_ID_TYPE_SHORT 0x02

/* Encoder/Decoder – all functions return length (>=0) or -1 on error. */
int mqttsn_encode_connect(uint8_t *buf, size_t buflen, const char *client_id,
                          int keepalive, int clean_session);
int mqttsn_decode_connack(const uint8_t *buf, size_t len, uint8_t *retcode);

int mqttsn_encode_register(uint8_t *buf, size_t buflen, uint16_t msg_id,
                           const char *topic_name);
int mqttsn_decode_regack(const uint8_t *buf, size_t len, uint16_t *topic_id,
                         uint16_t *msg_id, uint8_t *retcode);

int mqttsn_encode_subscribe_topicname(uint8_t *buf, size_t buflen,
                                      uint16_t msg_id, int qos,
                                      const char *topic_name);
int mqttsn_encode_subscribe_topicid(uint8_t *buf, size_t buflen,
                                    uint16_t msg_id, int qos, uint16_t topic_id,
                                    int id_type);
int mqttsn_decode_suback(const uint8_t *buf, size_t len, uint16_t *topic_id,
                         uint8_t *qos, uint16_t *msg_id, uint8_t *retcode);

int mqttsn_encode_publish(uint8_t *buf, size_t buflen, int qos, int retain,
                          uint16_t topic_id, int id_type, uint16_t msg_id,
                          const uint8_t *payload, size_t payload_len);
int mqttsn_decode_puback(const uint8_t *buf, size_t len, uint16_t *topic_id,
                         uint16_t *msg_id, uint8_t *retcode);

int mqttsn_encode_disconnect(uint8_t *buf, size_t buflen, uint16_t duration);
int mqttsn_encode_pingreq(uint8_t *buf, size_t buflen, const char *client_id);

int mqttsn_read_length(const uint8_t *buf, size_t len, uint16_t *out_len);

#endif
