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
#include "mqttsn_common.h"
#include <string.h>

/* Internal helper to write in network order (Big Endian) */
static void wr16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v);
}

int mqttsn_read_length(const uint8_t *buf, size_t len, uint16_t *out_len) {
  if (len < 2)
    return -1;

  uint8_t L = buf[0];
  if (L == 0x01) {
    if (len < 4)
      return -1;
    *out_len = (uint16_t)((buf[1] << 8) | buf[2]);

    return 3; /* Header length (0x01 + len_hi + len_lo) */
  } else {
    *out_len = L;

    return 1; /* 1-Byte length field */
  }
}

/* CONNECT */
int mqttsn_encode_connect(uint8_t *b, size_t blen, const char *client_id,
                          int keepalive, int clean_session) {
  size_t cid_len = strlen(client_id);
  size_t need = 6 + cid_len; /* 1 len + 1 type + 1 flags + 1 protocol id + 2
                                keepalive + cid */
  if (need > 255) {          /* Support long format */
    need += 2;               /* 0x01 + 2 Byte length */
    if (need > blen)
      return -1;

    b[0] = 0x01;
    uint16_t L = (uint16_t)(need);
    b[1] = (uint8_t)(L >> 8);
    b[2] = (uint8_t)L;
    b[3] = MQTTSN_CONNECT;
    b[4] = (uint8_t)((clean_session ? MQTTSN_FLAG_CLEAN : 0));
    b[5] = 0x01; /* Protocol ID 1 (MQTT-SN v1.2) */
    wr16(&b[6], (uint16_t)keepalive);
    memcpy(&b[8], client_id, cid_len);
    return (int)need;
  } else {
    if (need > blen)
      return -1;

    b[0] = (uint8_t)need;
    b[1] = MQTTSN_CONNECT;
    b[2] = (uint8_t)((clean_session ? MQTTSN_FLAG_CLEAN : 0));
    b[3] = 0x01;
    wr16(&b[4], (uint16_t)keepalive);
    memcpy(&b[6], client_id, cid_len);

    return (int)need;
  }
}

int mqttsn_decode_connack(const uint8_t *buf, size_t len, uint8_t *retcode) {
  uint16_t L;
  int hdr = mqttsn_read_length(buf, len, &L);
  if (hdr < 0 || len < (size_t)(hdr + 2))
    return -1;

  if (buf[hdr] != MQTTSN_CONNACK)
    return -1;

  *retcode = buf[hdr + 1];

  return hdr + 2;
}

/* REGISTER */
int mqttsn_encode_register(uint8_t *b, size_t blen, uint16_t msg_id,
                           const char *topic_name) {
  size_t tlen = strlen(topic_name);
  size_t need = 6 + tlen; /* len,type, topic_id(2)=0, msg_id(2), topic_name */
  if (need > blen)
    return -1;
  if (need > 255) {
    if (need + 2 > blen)
      return -1;

    b[0] = 0x01;
    b[1] = (need >> 8) & 0xff;
    b[2] = need & 0xff;
    b[3] = MQTTSN_REGISTER;
  } else {
    b[0] = (uint8_t)need;
    b[1] = MQTTSN_REGISTER;
  }

  size_t o = (need > 255) ? 4 : 2;
  b[o + 0] = 0;
  b[o + 1] = 0; /* Topic ID assigned by broker */
  wr16(&b[o + 2], msg_id);
  memcpy(&b[o + 4], topic_name, tlen);

  return (int)((need > 255) ? need + 2 : need);
}

int mqttsn_decode_regack(const uint8_t *buf, size_t len, uint16_t *topic_id,
                         uint16_t *msg_id, uint8_t *retcode) {
  uint16_t L;
  int hdr = mqttsn_read_length(buf, len, &L);
  //    if (hdr<0 || len<(size_t)(hdr+7)) return -1;
  /* REGACK total length = 7 (short header). Need >= hdr + 6 here. */
  if (hdr < 0 || len < (size_t)(hdr + 6))
    return -1;

  if (buf[hdr] != MQTTSN_REGACK)
    return -1;

  *topic_id = (uint16_t)((buf[hdr + 1] << 8) | buf[hdr + 2]);
  *msg_id = (uint16_t)((buf[hdr + 3] << 8) | buf[hdr + 4]);
  *retcode = buf[hdr + 5];

  return hdr + 6;
}

/* SUBSCRIBE */
static uint8_t qos_flag(int qos) {
  if (qos == 1)
    return MQTTSN_FLAG_QOS1;

  if (qos == 0)
    return MQTTSN_FLAG_QOS0;

  return MQTTSN_FLAG_QOSM1; /* -1 */
}

int mqttsn_encode_subscribe_topicname(uint8_t *b, size_t blen, uint16_t msg_id,
                                      int qos, const char *topic_name) {
  size_t tlen = strlen(topic_name);
  size_t need = 5 + tlen; /* len,type,flags,msg_id(2),topic */
  if (need > blen)
    return -1;
  if (need > 255) {
    if (need + 2 > blen)
      return -1;

    b[0] = 0x01;
    b[1] = (need >> 8) & 0xff;
    b[2] = need & 0xff;
    b[3] = MQTTSN_SUBSCRIBE;
  } else {
    b[0] = (uint8_t)need;
    b[1] = MQTTSN_SUBSCRIBE;
  }

  size_t o = (need > 255) ? 4 : 2;
  b[o] = (uint8_t)(qos_flag(qos) | MQTTSN_FLAG_TOPIC_ID_TYPE_NORMAL);
  wr16(&b[o + 1], msg_id);
  memcpy(&b[o + 3], topic_name, tlen);

  return (int)((need > 255) ? need + 2 : need);
}

int mqttsn_encode_subscribe_topicid(uint8_t *b, size_t blen, uint16_t msg_id,
                                    int qos, uint16_t topic_id, int id_type) {
  size_t need = 7; /* len,type,flags,msg_id(2),topic_id(2) */
  if (need > blen)
    return -1;

  b[0] = (uint8_t)need;
  b[1] = MQTTSN_SUBSCRIBE;
  b[2] = (uint8_t)(qos_flag(qos) | (id_type & 0x03));
  wr16(&b[3], msg_id);
  wr16(&b[5], topic_id);

  return (int)need;
}

int mqttsn_decode_suback(const uint8_t *buf, size_t len, uint16_t *topic_id,
                         uint8_t *qos, uint16_t *msg_id, uint8_t *retcode) {
  uint16_t L;
  int hdr = mqttsn_read_length(buf, len, &L);
  //    if (hdr<0 || len<(size_t)(hdr+8)) return -1;
  /* SUBACK total length = 8 -> need >= hdr + 7 */
  if (hdr < 0 || len < (size_t)(hdr + 7))
    return -1;

  if (buf[hdr] != MQTTSN_SUBACK)
    return -1;

  *qos = buf[hdr + 1] >> 5;
  *topic_id = (uint16_t)((buf[hdr + 2] << 8) | buf[hdr + 3]);
  *msg_id = (uint16_t)((buf[hdr + 4] << 8) | buf[hdr + 5]);
  *retcode = buf[hdr + 6];

  return hdr + 7;
}

/* PUBLISH/PUBACK */
int mqttsn_encode_publish(uint8_t *b, size_t blen, int qos, int retain,
                          uint16_t topic_id, int id_type, uint16_t msg_id,
                          const uint8_t *payload, size_t payload_len) {
  size_t need =
      7 + ((qos > 0) ? 2 : 0) +
      payload_len; /* len,type,flags,topic_id(2),[msg_id(2)],payload */
  if (need > blen)
    return -1;

  if (need > 255) {
    if (need + 2 > blen)
      return -1;

    b[0] = 0x01;
    b[1] = (need >> 8) & 0xff;
    b[2] = need & 0xff;
    b[3] = MQTTSN_PUBLISH;
  } else {
    b[0] = (uint8_t)need;
    b[1] = MQTTSN_PUBLISH;
  }

  size_t o = (need > 255) ? 4 : 2;
  uint8_t flags = 0;
  flags |= qos_flag(qos);
  if (retain)
    flags |= MQTTSN_FLAG_RETAIN;

  flags |= (uint8_t)(id_type & 0x03);
  b[o] = flags;
  wr16(&b[o + 1], topic_id);
  size_t p = o + 3;

  if (qos > 0) {
    wr16(&b[p], msg_id);
    p += 2;
  }
  
  memcpy(&b[p], payload, payload_len);

  return (int)((need > 255) ? need + 2 : need);
}

int mqttsn_decode_puback(const uint8_t *buf, size_t len, uint16_t *topic_id,
                         uint16_t *msg_id, uint8_t *retcode) {
  uint16_t L;
  int hdr = mqttsn_read_length(buf, len, &L);
  //    if (hdr<0 || len<(size_t)(hdr+7)) return -1;
  /* PUBACK total length = 7 -> need >= hdr + 6 */
  if (hdr < 0 || len < (size_t)(hdr + 6))
    return -1;

  if (buf[hdr] != MQTTSN_PUBACK)
    return -1;

  *topic_id = (uint16_t)((buf[hdr + 1] << 8) | buf[hdr + 2]);
  *msg_id = (uint16_t)((buf[hdr + 3] << 8) | buf[hdr + 4]);
  *retcode = buf[hdr + 5];

  return hdr + 6;
}

/* DISCONNECT/PINGREQ */
int mqttsn_encode_disconnect(uint8_t *b, size_t blen, uint16_t duration) {
  if (duration == 0) {
    if (blen < 2)
      return -1;

    b[0] = 2;
    b[1] = MQTTSN_DISCONNECT;

    return 2;
  } else {
    if (blen < 4)
      return -1;

    b[0] = 4;
    b[1] = MQTTSN_DISCONNECT;
    wr16(&b[2], duration);

    return 4;
  }
}

int mqttsn_encode_pingreq(uint8_t *b, size_t blen, const char *client_id) {
  size_t idlen = client_id ? strlen(client_id) : 0;
  size_t need = 2 + idlen;
  if (need > blen)
    return -1;

  b[0] = (uint8_t)need;
  b[1] = MQTTSN_PINGREQ;
  if (idlen)
    memcpy(&b[2], client_id, idlen);
    
  return (int)need;
}
