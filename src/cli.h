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
#ifndef CLI_H
#define CLI_H

#include <stdint.h>

/* Common CLI parameters for both tools. */
#define MAX_TOPICS 32 /* Maximum number of topics */

typedef struct {
  const char *host;
  int port;
  const char *client_id;
  int keepalive;          /* seconds */
  int qos;                /* -1, 0, 1 */
  const char *topic_name; /* optional, for backwards compatibility */
  const char *topic_names[MAX_TOPICS]; /* Array of topic names */
  int topic_count;                     /* number of topics */
  int have_topic_id;
  uint16_t topic_id; /* optional */
  int dtls;          /* 0=UDP, 1=DTLS */
  int tls;

  /* Optional app auth (MQTT) */
  const char *username; /* --username */
  const char *password; /* --password */

  /* SNI (optional own server name; if empty and host is a FQDN, we take host) */
  const char *sni;

  /* PSK */
  const char *psk_identity;
  const char *psk_hex;

  /* X.509 (optional) */
  const char *ca_path;
  const char *cert_path;
  const char *key_path;

  int timeout; /* Handshake/Operation seconds */
  int verbose; /* 0..2 */
  const char *iface;
} cli_common_t;

/* Publisher-specific */
typedef struct {
  cli_common_t common;
  const char *message;
  const char *message_file;
  int retain;
} cli_pub_t;

/* Subscriber-specific */
typedef enum { MATCH_EXACT = 0, MATCH_PREFIX = 1 } match_t;

typedef struct {
  cli_common_t common;
  match_t match;
  int recv_timeout; /* seconds */
} cli_sub_t;

/* Parser; on error: -1 and Usage on stderr. */
int parse_pub_args(int argc, char **argv, cli_pub_t *out);
int parse_sub_args(int argc, char **argv, cli_sub_t *out);

/* Short usage (for README and --help). */
void usage_pub(const char *prog);
void usage_sub(const char *prog);

#endif
