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
#include "mqtt_proto.h"
#include "util.h"
#include <string.h>

/* Remaining Length (MQTT variable integer) */
static int rl_write(uint8_t *out, size_t cap, size_t value, size_t *nbytes) {
    size_t i=0;

    do {
        if (i >= cap) 
            return -1;

        uint8_t d = value % 128;
        value /= 128;

        if (value)
            d |= 0x80;

        out[i++] = d;
    } while (value);

    *nbytes = i; 
    
    return 0;
}

static int rl_read(const uint8_t *p, size_t len, size_t *value, size_t *nbytes) {
    size_t mul=1, v=0; size_t i=0;

    while (i<len && i<4) {
        uint8_t d=p[i++];
        v += (d & 127)*mul;

        if (!(d & 0x80)) {
            *value = v;
            *nbytes = i;
            return 0;
        }

        if (!(d & 0x80)) {
            *value=v; *nbytes=i; 
            return 0; 
        }
        mul *= 128;
    }

    return -1;
}

static void wr16(uint8_t *p, uint16_t v){ p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)(v); }
static uint16_t rd16(const uint8_t *p){ return (uint16_t)((p[0]<<8)|p[1]); }

static size_t put_str(uint8_t *b, size_t cap, size_t off, const char *s) {
    size_t L = strlen(s);

    if (off+2+L > cap) 
        return (size_t)-1;
    wr16(b+off, (uint16_t)L);
    memcpy(b+off+2, s, L);
    
    return off+2+L;
}

int mqtt_encode_connect(uint8_t *buf, size_t buflen,
                        const char *client_id, int keepalive_s, int clean_start,
                        const char *username, const char *password) {
    /* CONNECT v3.1.1 */
    uint8_t vh[10]; /* Protocol Name/Level/Flags/Keepalive */
    size_t off=0;
    /* Fixed header reserved, write later */
    /* Variable header */
    off = 0;
    off = put_str(vh, sizeof(vh), off, "MQTT"); 
    
    if (off==(size_t)-1) 
        return -1;

    if (off+4 > sizeof(vh)) 
        return -1;

    vh[off++] = 4; /* Protocol Level 4 = MQTT 3.1.1 */
    uint8_t flags = 0;

    if (clean_start) 
        flags |= 0x02;        /* Clean Session (bit1) */
    if (username && *username) 
        flags |= 0x80;  /* Username flag (bit7) */
    if (password && *password) 
        flags |= 0x40;  /* Password flag (bit6) */
    vh[off++] = flags;
    wr16(vh+off, (uint16_t)keepalive_s);
    off+=2;

    /* Payload: ClientID [, Username] [, Password]  (without Will in this minimal implementation) */
    uint8_t pl[512];
    size_t po=0;
    po = put_str(pl, sizeof(pl), po, client_id); 
    if (po==(size_t)-1)
        return -1;

    if (username && *username) {
        po = put_str(pl, sizeof(pl), po, username); 
        if (po==(size_t)-1) 
            return -1;
    }

    if (password && *password) {
        po = put_str(pl, sizeof(pl), po, password);
        if (po==(size_t)-1) 
            return -1;
    }

    size_t rem_len = off + po;
    uint8_t rl[4]; size_t rl_n=0;

    if (rl_write(rl, sizeof(rl), rem_len, &rl_n))
        return -1;

    size_t need = 1 + rl_n + off + po;

    if (need > buflen) 
        return -1;

    size_t w=0;
    buf[w++] = (MQTT_PKT_CONNECT<<4);
    memcpy(buf+w, rl, rl_n);
    w+=rl_n;
    memcpy(buf+w, vh, off);
    w+=off;
    memcpy(buf+w, pl, po);
    w+=po;

    log_info("CONNECT OK");
    return (int)w;
}

int mqtt_decode_connack(const uint8_t *buf, size_t len, int *session_present, int *rc) {
    if (len<4)
        return -1;

    if ((buf[0]>>4) != MQTT_PKT_CONNACK)
        return -1;

    size_t rlen=0, rn=0;

    if (rl_read(buf+1, len-1, &rlen, &rn))
        return -1;

    /* Check if we have enough bytes: Fixed Header (1) + Remaining Length (rn) + Variable Header (2) */
    if (1 + rn + 2 > len)
        return -1;

    size_t off=1+rn;
    *session_present = buf[off] & 0x01;
    *rc = buf[off+1];

    log_info("CONNACK OK");
    return 0;
}

int mqtt_encode_subscribe(uint8_t *buf, size_t buflen, uint16_t msg_id,
                          const char *topic, int qos) {
    uint8_t pl[512];
    size_t po=0;
    po = put_str(pl, sizeof(pl), po, topic);
    
    if (po==(size_t)-1)
        return -1;

    if (po+1 > sizeof(pl))
        return -1;

    pl[po++] = (uint8_t)(qos & 0x03);

    uint8_t vh[2];
    wr16(vh, msg_id);

    size_t rem_len = sizeof(vh)+po;
    uint8_t rl[4]; size_t rl_n=0;
    if (rl_write(rl, sizeof(rl), rem_len, &rl_n))
        return -1;

    size_t need = 1+rl_n+sizeof(vh)+po;
    if (need>buflen)
        return -1;

    size_t w=0;
    buf[w++] = (MQTT_PKT_SUBSCRIBE<<4) | 0x02; /* bit1 must be 1 */
    memcpy(buf+w, rl, rl_n); 
    w+=rl_n;
    memcpy(buf+w, vh, sizeof(vh));
    w+=sizeof(vh);
    memcpy(buf+w, pl, po);
    w+=po;

    log_info("SUBSCRIBE OK");
    return (int)w;
}

int mqtt_decode_suback(const uint8_t *buf, size_t len, uint16_t *msg_id, int *granted_qos) {
    if (len<5)
        return -1;

    if ((buf[0]>>4) != MQTT_PKT_SUBACK)
        return -1;

    size_t rlen=0, rn=0;
    if (rl_read(buf+1, len-1, &rlen, &rn))
        return -1;

    size_t off=1+rn;
    if (off+2 > len)
        return -1;

    *msg_id = rd16(buf+off);
        off+=2;

    if (off >= len)
        return -1;

    *granted_qos = buf[off]; /* 0x80 = Failure */

    log_info("SUBACK OK");
    return 0;
}

int mqtt_encode_publish(uint8_t *buf, size_t buflen,
                        int qos, int retain, int dup,
                        const char *topic, uint16_t msg_id,
                        const uint8_t *payload, size_t paylen, size_t *out_len) {
    uint8_t vh[512]; size_t vo=0;
    vo = put_str(vh, sizeof(vh), vo, topic);
    if (vo==(size_t)-1)
        return -1;

    if (qos>0) { if (vo+2>sizeof(vh))
        return -1;
    
    wr16(vh+vo, msg_id); vo+=2; }
    size_t rem_len = vo + paylen;
    uint8_t rl[4]; size_t rn=0;
    if (rl_write(rl, sizeof(rl), rem_len, &rn))
        return -1;

    size_t need = 1+rn+vo+paylen;
    if (need>buflen)
        return -1;

    uint8_t hdr = (MQTT_PKT_PUBLISH<<4);
    if (dup)
        hdr |= 0x08;
    hdr |= (uint8_t)((qos & 0x03)<<1);
    if (retain)
        hdr |= 0x01;

    size_t w=0;
    buf[w++] = hdr;
    memcpy(buf+w, rl, rn);
    w+=rn;
    memcpy(buf+w, vh, vo);
    w+=vo;

    if (paylen)
        memcpy(buf+w, payload, paylen), w+=paylen;
    *out_len = w;

    log_info("PUBLISH OK");
    return 0;
}

int mqtt_encode_puback(uint8_t *buf, size_t buflen, uint16_t msg_id) {
    if (buflen < 4)
        return -1;

    buf[0] = (MQTT_PKT_PUBACK<<4);
    buf[1] = 0x02;
    wr16(buf+2, msg_id);

    log_info("PUBACK OK");
    return 4;
}

int mqtt_decode_publish_fixed(const uint8_t *buf, size_t len,
                              int *qos, int *retain, int *dup,
                              size_t *remaining_len) {
    if (len<2)
        return -1;

    if ((buf[0]>>4) != MQTT_PKT_PUBLISH)
        return -1;
    *dup = !!(buf[0] & 0x08);
    *qos = (buf[0] >> 1) & 0x03;
    *retain = !!(buf[0] & 0x01);
    size_t rl=0, rn=0;
    
    if (rl_read(buf+1, len-1, &rl, &rn))
        return -1;

    *remaining_len = rl;

    return (int)(1+rn);
}

int mqtt_extract_topic_msgid(const uint8_t *buf, size_t len,
                             char *topic, size_t topic_cap,
                             uint16_t *msg_id,
                             const uint8_t **payload, size_t *paylen) {
    int qos, retain, dup;
    size_t rem;
    int off = mqtt_decode_publish_fixed(buf, len, &qos, &retain, &dup, &rem);

    if (off < 0)
        return -1;
    size_t pos = (size_t)off;

    if (pos+2 > len)
        return -1;
    uint16_t tlen = rd16(buf+pos);
    pos+=2;
    size_t stlen = (size_t)tlen;

    if ((size_t)pos + stlen > (size_t)len || stlen + 1 > topic_cap)
	    return -1;

    memcpy(topic, buf+pos, tlen);
    topic[tlen]='\0'; pos+=tlen;

    if (qos>0) { 
        if (pos+2>len)
            return -1;
        *msg_id = rd16(buf+pos);
        pos+=2;
    } else {
        *msg_id=0;
    }
    *payload = buf+pos;
    *paylen = len - pos;

    log_info("PUBLISH OK");
    return qos;
}

int mqtt_encode_pingreq(uint8_t *buf, size_t buflen){ if (buflen<2) return -1; buf[0]=(MQTT_PKT_PINGREQ<<4); buf[1]=0; return 2; }
int mqtt_encode_disconnect(uint8_t *buf, size_t buflen){ if (buflen<2) return -1; buf[0]=(MQTT_PKT_DISCONNECT<<4); buf[1]=0; return 2; }
