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
#include "cli.h"
#include "mqttsn_client.h"
#include "mqttsn_common.h"
#include "util.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>

static volatile int g_stop = 0;
static void on_sig(int s) {
  (void)s;
  g_stop = 1;
}

/* Mapping between Topic-ID and Topic-Name */
typedef struct {
  uint16_t topic_id;
  const char *topic_name;
} topic_map_t;

int main(int argc, char **argv) {
  signal(SIGINT, on_sig);
  signal(SIGTERM, on_sig);

  cli_sub_t cli;
  if (parse_sub_args(argc, argv, &cli) != 0)
    return EXIT_CLI;

  uint8_t psk[256];
  size_t psk_len = 0;
  if (cli.common.psk_hex) {
    int r = hex_to_bin(cli.common.psk_hex, psk, sizeof(psk));
    if (r < 0) {
      log_err("Invalid PSK hex key.");

      return EXIT_CLI;
    }

    /* Set the PSK length */
    psk_len = (size_t)r;
  }

  mqttsn_client_t c;
  memset(&c, 0, sizeof(c));
  c.bind_iface = cli.common.iface;

  if (mqttsn_client_connect(&c, cli.common.host, cli.common.port,
                            cli.common.sni, cli.common.dtls,
                            cli.common.psk_identity, (psk_len ? psk : NULL),
                            psk_len, cli.common.ca_path, cli.common.cert_path,
                            cli.common.key_path, cli.common.client_id,
                            cli.common.keepalive, cli.common.timeout) != 0) {
    return EXIT_NET_HANDSHAKE;
  }

  /* Topic-Mapping for multiple topics */
  topic_map_t topic_map[MAX_TOPICS];
  int topic_map_count = 0;

  /* Subscribe to each topic */
  int topic_count = cli.common.topic_count > 0 ? cli.common.topic_count : 1;
  const char **topics = cli.common.topic_count > 0 ? cli.common.topic_names
                                                   : &cli.common.topic_name;

  if (cli.common.have_topic_id) {
    /* Single topic with predefined Topic-ID */
    if (mqttsn_client_subscribe_id(&c, cli.common.topic_id,
                                   MQTTSN_FLAG_TOPIC_ID_TYPE_PREDEF,
                                   cli.common.qos) != 0) {
      log_err("SUBSCRIBE (ID) failed.");
      mqttsn_client_close(&c);

      return EXIT_BROKER_PROTO;
    }

    topic_map[topic_map_count].topic_id = cli.common.topic_id;
    topic_map[topic_map_count].topic_name =
        cli.common.topic_name ? cli.common.topic_name : "(unknown)";
    topic_map_count++;
    log_info("SUBACK OK, Topic-ID=%u", cli.common.topic_id);
  } else {
    /* Multiple topics per name subscribed */
    for (int i = 0; i < topic_count; i++) {
      uint16_t topic_id = 0;
      if (mqttsn_client_subscribe_name(&c, topics[i], cli.common.qos,
                                       &topic_id) != 0) {
        log_err("SUBSCRIBE failed for topic: %s", topics[i]);
        mqttsn_client_close(&c);

        return EXIT_BROKER_PROTO;
      }

      topic_map[topic_map_count].topic_id = topic_id;
      topic_map[topic_map_count].topic_name = topics[i];
      topic_map_count++;
      log_info("SUBACK OK, Topic-ID=%u, Topic=%s", topic_id, topics[i]);
    }
  }

  /* Wait for matching messages or timeout */
  uint64_t t0 = now_ms();
  int timeout_ms = cli.recv_timeout * 1000;
  uint8_t buf[65536];

  for (;;) {
    if (g_stop) {
      log_info("Abort signal received.");
      mqttsn_client_close(&c);
      return EXIT_OK;
    }

    int wait = 200; /* Poll in 200ms-chunks, to respect g_stop */
    int r = mqttsn_client_recv(&c, buf, sizeof(buf), wait);
    if (r < 0) {
      log_err("recv error.");
      mqttsn_client_close(&c);

      return EXIT_NET_HANDSHAKE;
    }

    if (r == 0) {
      if (timeout_ms > 0 && timed_out(t0, timeout_ms)) {
        log_info("Timeout reached.");
        mqttsn_client_close(&c);

        return EXIT_TIMEOUT;
      }

      /* Continue polling */
      continue;
    }

    /* Minimal parse: PUBLISH? */
    uint16_t L;
    int hdr = mqttsn_read_length(buf, r, &L);
    if (hdr < 0 || r < hdr + 2)
      continue;

    uint8_t type = buf[hdr];
    if (type == MQTTSN_PUBLISH) {
      /* flags, topic_id(2), [msg_id(2)], payload... */
      if (r < hdr + 5)
        continue;

      uint8_t flags = buf[hdr + 1];
      uint16_t tid = (uint16_t)((buf[hdr + 2] << 8) | buf[hdr + 3]);
      int qos = (flags >> 5) & 0x3;
      size_t pos = hdr + 4;
      if (qos == 1)
        pos += 2; /* skip msg_id */

      /* Search topic name for this topic ID */
      const char *matched_topic = NULL;
      for (int i = 0; i < topic_map_count; i++) {
        if (topic_map[i].topic_id == tid) {
          matched_topic = topic_map[i].topic_name;

          break;
        }
      }

      if (matched_topic) {
        /* Activity -> reset timeout */
        t0 = now_ms();

        /* Output: Topic-Name followed by payload */
        fprintf(stdout, "%s ", matched_topic);
        fwrite(&buf[pos], 1, r - pos, stdout);
        fputc('\n', stdout);
        fflush(stdout);

        /* If single receive with old behavior: terminate
         * (Backward compatibility) Only if exactly one topic is subscribed
         */
        if (topic_map_count == 1 && topic_count == 1) {
          mqttsn_client_close(&c);

          return EXIT_OK;
        }
      }
    }
    /* Other packet – ignore */
  }
}
