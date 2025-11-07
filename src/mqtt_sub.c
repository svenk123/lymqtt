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
#include "mqtt_client.h"
#include "mqtt_proto.h"
#include "util.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>

static volatile int g_stop = 0;
static void on_sig(int s) {
  (void)s;
  g_stop = 1;
}

static int match_ok(match_t m, const char *sub, const char *topic) {
  if (m == MATCH_EXACT)
    return strcmp(sub, topic) == 0;

  if (m == MATCH_PREFIX)
    return strncmp(topic, sub, strlen(sub)) == 0;

  return 0;
}

int main(int argc, char **argv) {
  signal(SIGINT, on_sig);
  signal(SIGTERM, on_sig);

  cli_sub_t cli;
  if (parse_sub_args(argc, argv, &cli) != 0)
    return EXIT_CLI;
  g_log_level = cli.common.verbose;

  if (cli.common.have_topic_id) {
    log_info("Note: --topic-id is ignored for MQTT, use --topic.");
  }

  uint8_t psk[256];
  size_t psk_len = 0;
  if (cli.common.psk_hex) {
    int r = hex_to_bin(cli.common.psk_hex, psk, sizeof(psk));
    if (r < 0) {
      log_err("Invalid PSK hex key.");

      return EXIT_CLI;
    }

    psk_len = (size_t)r;
  }

  mqtt_client_t c;
  memset(&c, 0, sizeof(c));
  c.bind_iface = cli.common.iface;
  int use_tls = 0;
  if (cli.common.tls)
    use_tls = 1;
  else if (cli.common.dtls) {
    log_info("Note: '--dtls' for MQTT (TCP) is interpreted as TLS. "
             "Please use '--tls' from now on.");
    use_tls = 1;
  }

  if (mqtt_client_connect(
          &c, cli.common.host, cli.common.port, cli.common.sni, use_tls,
          cli.common.psk_identity, (psk_len ? psk : NULL), psk_len,
          cli.common.ca_path, cli.common.cert_path, cli.common.key_path,
          cli.common.client_id, cli.common.username, cli.common.password,
          cli.common.keepalive, cli.common.timeout) != 0) {
    return EXIT_NET_HANDSHAKE;
  }

  /* Subscribe to each topic */
  int topic_count = cli.common.topic_count > 0 ? cli.common.topic_count : 1;
  const char **topics = cli.common.topic_count > 0 ? cli.common.topic_names
                                                   : &cli.common.topic_name;

  for (int i = 0; i < topic_count; i++) {
    if (mqtt_client_subscribe(&c, topics[i], cli.common.qos) != 0) {
      log_err("SUBSCRIBE failed for topic: %s", topics[i]);
      mqtt_client_close(&c);

      return EXIT_BROKER_PROTO;
    }

    log_info("SUBACK OK, Topic: %s", topics[i]);
  }

  uint64_t start = now_ms();
  const int to_ms = (cli.recv_timeout > 0 ? cli.recv_timeout : 0) * 1000;

  while (!g_stop) {
    mqtt_client_maybe_ping(&c);

    uint8_t rx[65536];
    int r = mqtt_client_recv_raw(&c, rx, sizeof(rx), 500);
    if (r == 0) {
      if (to_ms > 0 && timed_out(start, to_ms)) {
        log_info("Receive timeout.");

        break;
      }

      continue;
    }

    if (r < 0) {
      log_err("Network error.");

      break;
    }

    start = now_ms(); /* Activity -> extend timeout */

    uint8_t type = rx[0] >> 4;
    if (type == MQTT_PKT_PUBLISH) {
      char topic[512];
      uint16_t mid = 0;
      const uint8_t *pl = NULL;
      size_t pllen = 0;
      int qos = mqtt_extract_topic_msgid(rx, r, topic, sizeof(topic), &mid, &pl,
                                         &pllen);
      if (qos < 0)
        continue;

      /* Check if the topic matches one of our subscribed topics */
      int matched = 0;
      const char *matched_topic = NULL;

      for (int i = 0; i < topic_count; i++) {
        if (match_ok(cli.match, topics[i], topic)) {
          matched = 1;
          matched_topic = topics[i];

          break;
        }
      }

      /* If the topic does not match, continue */
      if (!matched)
        continue;

      /* Output: Topic name followed by message */
      fprintf(stdout, "%s: ", matched_topic);
      fwrite(pl, 1, pllen, stdout);
      fputc('\n', stdout);
      fflush(stdout);

      if (qos == 1) {
        uint8_t ack[4];
        int L = mqtt_encode_puback(ack, sizeof(ack), mid);
        if (L > 0)
          net_tls_send(&c.net, ack, L);
      }
    } /* else: ignore PINGRESP etc. */
  }

  mqtt_client_close(&c);
  
  return EXIT_OK;
}
