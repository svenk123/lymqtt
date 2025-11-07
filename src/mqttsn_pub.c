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

  /* Get file size */
  long sz = ftell(f);
  if (sz < 0 || sz > 1024 * 1024) {
    fclose(f);

    return -1;
  }

  /* Rewind file pointer to the beginning */
  rewind(f);

  /* Allocate memory for the file content */
  uint8_t *buf = (uint8_t *)malloc((size_t)sz);
  if (!buf) {
    fclose(f);

    return -1;
  }

  /* Read the file content into the buffer */
  if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
    fclose(f);
    free(buf);

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

  /* Prepare PSK buffer (optional). */
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

  uint16_t topic_id = cli.common.topic_id;
  int id_type = MQTTSN_FLAG_TOPIC_ID_TYPE_NORMAL;
  if (!cli.common.have_topic_id) {
    if (mqttsn_client_register(&c, cli.common.topic_name, &topic_id) != 0) {
      log_err("REGISTER failed.");
      mqttsn_client_close(&c);

      return EXIT_BROKER_PROTO;
    }

    log_info("Topic-ID erhalten: %u", topic_id);
  } else {
    id_type =
        MQTTSN_FLAG_TOPIC_ID_TYPE_PREDEF; /* Broker could use predefined IDs */
  }

  uint8_t *payload = NULL;
  size_t payload_len = 0;
  if (cli.message) {
    payload = (uint8_t *)cli.message;
    payload_len = strlen(cli.message);
  } else {
    if (load_message(cli.message_file, &payload, &payload_len) != 0) {
      log_err("File could not be read: %s", cli.message_file);
      mqttsn_client_close(&c);

      return EXIT_IO;
    }
  }

  int rc = mqttsn_client_publish(&c, cli.common.qos, cli.retain, topic_id,
                                 id_type, payload, payload_len);
  if (!cli.message)
    free(payload);

  /* PUBACK timeout */
  if (rc == -2) {
    log_err("PUBACK timeout.");
    mqttsn_client_close(&c);

    return EXIT_TIMEOUT;
  }
  if (rc != 0) {
    log_err("Publish failed.");
    mqttsn_client_close(&c);

    return EXIT_BROKER_PROTO;
  }

  mqttsn_client_close(&c);
  
  return EXIT_OK;
}
