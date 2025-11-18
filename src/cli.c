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
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int to_int(const char *s, int *out) {
  char *end = NULL;
  long v = strtol(s, &end, 10);

  if (!s || *s == '\0' || !end || *end != '\0')
    return -1;

  *out = (int)v;

  return 0;
}

static void common_defaults(cli_common_t *c) {
  memset(c, 0, sizeof(*c));
  c->port = 1884; /* typical MQTT-SN UDP port */
  c->keepalive = 30;
  c->qos = 0;
  c->timeout = 5;
  c->verbose = 0;
  c->sni = NULL;
  c->topic_count = 0;
}

void usage_pub(const char *p) {
  fprintf(stderr,
          "Usage: %s --host H --port P --interface I --client-id ID "
          "[--keepalive S] [--qos -1|0|1]\n"
          "            (--topic NAME | --topic-id N) [--sni NAME]\n"
          "            [--tls | --dtls] [--psk-identity I --psk-key HEX | --ca "
          "CA --cert CERT --key KEY]\n"
          "            [--username U --password P]\n"
          "            [--timeout S] [--verbose]\n"
          "            (--message TXT | --message-file PATH) [--retain]\n",
          p);
}

void usage_sub(const char *p) {
  fprintf(
      stderr,
      "Usage: %s --host H --port P --interface I --client-id ID [--keepalive "
      "S] [--qos -1|0|1]\n"
      "            [--topic NAME]... [--topic-id N] [--match exact|prefix]\n"
      "            [--sni NAME]\n"
      "            [--tls | --dtls] [--psk-identity I --psk-key HEX | --ca CA "
      "--cert CERT --key KEY]\n"
      "            [--username U --password P]\n"
      "            [--timeout S] [--recv-timeout S] [--verbose] [--once]\n"
      "            --topic kann mehrfach angegeben werden\n",
      p);
}

static int parse_common(int *i, int argc, char **argv, cli_common_t *c) {
  const char *a = argv[*i];
  if (!strcmp(a, "--host") && *i + 1 < argc) {
    c->host = argv[++*i];
  } else if (!strcmp(a, "--sni") && *i + 1 < argc) {
    c->sni = argv[++*i];
  } else if (!strcmp(a, "--port") && *i + 1 < argc) {
    if (to_int(argv[++*i], &c->port))
      return -1;
  } else if (!strcmp(a, "--interface") && *i + 1 < argc) {
    c->iface = argv[++*i];
  } else if (!strcmp(a, "--client-id") && *i + 1 < argc) {
    c->client_id = argv[++*i];
  } else if (!strcmp(a, "--keepalive") && *i + 1 < argc) {
    if (to_int(argv[++*i], &c->keepalive))
      return -1;
  } else if (!strcmp(a, "--qos") && *i + 1 < argc) {
    if (to_int(argv[++*i], &c->qos))
      return -1;
  } else if (!strcmp(a, "--topic") && *i + 1 < argc) {
    const char *topic = argv[++*i];

    if (c->topic_count < MAX_TOPICS) {
      c->topic_names[c->topic_count++] = topic;
      /* For backwards compatibility: set topic_name to the last topic */
      c->topic_name = topic;
    } else {
      log_err("Too many topics (maximum: %d)", MAX_TOPICS);
      return -1;
    }
  } else if (!strcmp(a, "--topic-id") && *i + 1 < argc) {
    int v;

    if (to_int(argv[++*i], &v))
      return -1;

    c->have_topic_id = 1;
    c->topic_id = (uint16_t)v;
  } else if (!strcmp(a, "--dtls")) {
    c->dtls = 1;
  } else if (!strcmp(a, "--tls")) {
    c->tls = 1;
  } else if (!strcmp(a, "--username") && *i + 1 < argc) {
    c->username = argv[++*i];
  } else if (!strcmp(a, "--password") && *i + 1 < argc) {
    c->password = argv[++*i];
  } else if (!strcmp(a, "--psk-identity") && *i + 1 < argc) {
    c->psk_identity = argv[++*i];
  } else if (!strcmp(a, "--psk-key") && *i + 1 < argc) {
    c->psk_hex = argv[++*i];
  } else if (!strcmp(a, "--ca") && *i + 1 < argc) {
    c->ca_path = argv[++*i];
  } else if (!strcmp(a, "--cert") && *i + 1 < argc) {
    c->cert_path = argv[++*i];
  } else if (!strcmp(a, "--key") && *i + 1 < argc) {
    c->key_path = argv[++*i];
  } else if (!strcmp(a, "--timeout") && *i + 1 < argc) {
    if (to_int(argv[++*i], &c->timeout))
      return -1;
  } else if (!strcmp(a, "--verbose")) {
    c->verbose++;
  } else if (!strcmp(a, "--help")) {
    return -2;
  } else
    return 1;

  return 0;
}

int parse_pub_args(int argc, char **argv, cli_pub_t *out) {
  common_defaults(&out->common);
  out->retain = 0;

  for (int i = 1; i < argc; ++i) {
    int r = parse_common(&i, argc, argv, &out->common);

    if (r == -2) {
      usage_pub(argv[0]);
      return -1;
    }

    if (r == 0)
      continue;

    if (!strcmp(argv[i], "--message") && i + 1 < argc)
      out->message = argv[++i];
    else if (!strcmp(argv[i], "--message-file") && i + 1 < argc)
      out->message_file = argv[++i];
    else if (!strcmp(argv[i], "--retain"))
      out->retain = 1;
    else {
      log_err("Unbekannte Option: %s", argv[i]);
      usage_pub(argv[0]);

      return -1;
    }
  }
  /* Validity checks */
  if (!out->common.host || !out->common.client_id) {
    usage_pub(argv[0]);

    return -1;
  }
  if (!out->common.topic_name && !out->common.have_topic_id) {
    log_err("Topic missing (--topic or --topic-id).");

    return -1;
  }
  if (out->message && out->message_file) {
    log_err("Only --message OR --message-file allowed.");

    return -1;
  }
  if (!out->message && !out->message_file) {
    log_err("Message missing (--message or --message-file).");

    return -1;
  }

  /* Note: the actual redirection is done in mqtt_pub.c / mqtt_sub.c */
  if (out->common.dtls && !out->common.tls) {
    log_info("Note: When using MQTT (TCP), '--dtls' is interpreted as TLS. "
             "Please use '--tls' from now on.");
  }

  if (out->common.dtls) {
    /* PSK default, X.509 optional */
    if (!out->common.ca_path &&
        (!out->common.psk_identity || !out->common.psk_hex)) {
      log_info("DTLS without X.509: PSK parameters are incomplete – trying "
               "anyway (broker-specific).");
    }
  }
  g_log_level = out->common.verbose;

  return 0;
}

int parse_sub_args(int argc, char **argv, cli_sub_t *out) {
  common_defaults(&out->common);
  out->match = MATCH_EXACT;
  out->recv_timeout = 30;
  out->once = 0;

  for (int i = 1; i < argc; ++i) {
    int r = parse_common(&i, argc, argv, &out->common);

    if (r == -2) {
      usage_sub(argv[0]);

      return -1;
    }

    if (r == 0)
      continue;

    if (!strcmp(argv[i], "--match") && i + 1 < argc) {
      const char *m = argv[++i];

      if (!strcmp(m, "exact"))
        out->match = MATCH_EXACT;
      else if (!strcmp(m, "prefix"))
        out->match = MATCH_PREFIX;
      else {
        log_err("Invalid --match value.");

        return -1;
      }
    } else if (!strcmp(argv[i], "--recv-timeout") && i + 1 < argc) {
      if (to_int(argv[++i], &out->recv_timeout))
        return -1;
    } else if (!strcmp(argv[i], "--once")) {
      out->once = 1;
    } else {
      log_err("Unknown option: %s", argv[i]);
      usage_sub(argv[0]);

      return -1;
    }
  }
  if (!out->common.host || !out->common.client_id) {
    usage_sub(argv[0]);
    return -1;
  }

  if (out->common.topic_count == 0 && !out->common.have_topic_id) {
    log_err("  Topic missing (--topic or --topic-id).");

    return -1;
  }

  g_log_level = out->common.verbose;

  return 0;
}
