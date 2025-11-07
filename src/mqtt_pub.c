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
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int load_message(const char *path, uint8_t **out, size_t *outlen) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;

  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);

    return -1;
  }

  long sz = ftell(f);
  if (sz < 0 || sz > 8 * 1024 * 1024) {
    fclose(f);

    return -1;
  }

  rewind(f);
  uint8_t *buf = (uint8_t *)malloc((size_t)sz);
  if (!buf) {
    fclose(f);

    return -1;
  }

  if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
    free(buf);
    fclose(f);

    return -1;
  }

  fclose(f);
  *out = buf;
  *outlen = (size_t)sz;

  return 0;
}

int main(int argc, char **argv) {
  cli_pub_t cli;
  if (parse_pub_args(argc, argv, &cli) != 0)
    return EXIT_CLI;
  g_log_level = cli.common.verbose;

  if (cli.common.have_topic_id) {
    log_info("Note: --topic-id is ignored for MQTT, use --topic.");
  }

  /* Prepare PSK (optional) */
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

  uint8_t *msg = NULL;
  size_t msglen = 0;
  if (cli.message) {
    msg = (uint8_t *)cli.message;
    msglen = strlen(cli.message);
  } else if (cli.message_file) {
    if (load_message(cli.message_file, &msg, &msglen) != 0) {
      mqtt_client_close(&c);
      log_err("Failed to load message file: %s", cli.message_file);
      return EXIT_IO;
    }
  }

  int rc = mqtt_client_publish(&c, cli.common.qos, cli.retain,
                               cli.common.topic_name, msg, msglen);
  if (cli.message_file && msg && msg != (uint8_t *)cli.message)
    free(msg);
  mqtt_client_close(&c);

  if (rc != 0)
    return EXIT_BROKER_PROTO;
    
  return EXIT_OK;
}
