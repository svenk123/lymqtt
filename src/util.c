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
#include "util.h"
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#ifdef __linux__
#include <linux/if.h>
#endif
#include <sys/time.h>

int g_log_level = 0;

static void vlog_at(int level, const char *prefix, const char *fmt,
                    va_list ap) {
  if (g_log_level < level)
    return;

  fprintf(stderr, "%s", prefix);
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
}

void log_err(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vlog_at(0, "[ERR] ", fmt, ap);
  va_end(ap);
}

void log_info(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vlog_at(1, "[INF] ", fmt, ap);
  va_end(ap);
}

void log_dbg(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vlog_at(2, "[DBG] ", fmt, ap);
  va_end(ap);
}

int get_iface_addr(const char *ifname, int family, struct sockaddr_storage *sa,
                   socklen_t *salen) {
  if (!ifname || !sa || !salen)
    return -1;

  /* Get interface addresses */
  struct ifaddrs *ifa = NULL;
  if (getifaddrs(&ifa) != 0)
    return -1;

  int rc = -1;
  for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
    if (!p->ifa_addr || !p->ifa_name)
      continue;

    if (strcmp(p->ifa_name, ifname) != 0)
      continue;

    int fam = p->ifa_addr->sa_family;
    if (family != AF_UNSPEC && fam != family)
      continue;

    if (fam != AF_INET && fam != AF_INET6)
      continue;

    memset(sa, 0, sizeof(*sa));
    memcpy(sa, p->ifa_addr,
           (fam == AF_INET) ? sizeof(struct sockaddr_in)
                            : sizeof(struct sockaddr_in6));
    *salen = (fam == AF_INET) ? sizeof(struct sockaddr_in)
                              : sizeof(struct sockaddr_in6);
    rc = 0;

    break;
  }

  freeifaddrs(ifa);

  return rc;
}

int net_bind_to_interface(int fd, const char *ifname, int family) {
  if (!ifname || !*ifname)
    return 0; /* nothing to do */

#ifdef SO_BINDTODEVICE
  /* Try 1: true interface binding (Linux). Requires root/CAP_NET_RAW. */
  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
                 (socklen_t)strlen(ifname)) == 0) {
    return 0;
  }
  /* Falls with EPERM without Root. Then fallback. */
#endif

  /* Fallback: bind to the IF source */
  struct sockaddr_storage sa;
  socklen_t salen = 0;
  if (get_iface_addr(ifname, (family == AF_UNSPEC ? AF_INET : family), &sa,
                     &salen) != 0) {
    /* Try IPv6 as second chance, if family was unclear */
    if (family == AF_UNSPEC &&
        get_iface_addr(ifname, AF_INET6, &sa, &salen) != 0) {
      return -1;
    }
  }

  if (bind(fd, (struct sockaddr *)&sa, salen) != 0) {
    return -1;
  }

  return 0;
}

static int hexval(int c) {
  if (c >= '0' && c <= '9')
    return c - '0';

  if (c >= 'a' && c <= 'f')
    return 10 + (c - 'a');

  if (c >= 'A' && c <= 'F')
    return 10 + (c - 'A');

  return -1;
}

int hex_to_bin(const char *hex, uint8_t *out, size_t outlen) {
  size_t n = strlen(hex);
  if (n % 2 != 0)
    return -1;

  size_t bytes = n / 2;
  if (bytes > outlen)
    return -1;

  for (size_t i = 0; i < bytes; ++i) {
    int hi = hexval(hex[2 * i]);
    int lo = hexval(hex[2 * i + 1]);
    if (hi < 0 || lo < 0)
      return -1;

    out[i] = (uint8_t)((hi << 4) | lo);
  }

  /* Return the number of bytes converted */
  return (int)bytes;
}

uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);

  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

int timed_out(uint64_t start_ms, uint64_t timeout_ms) {
  uint64_t n = now_ms();
  
  return (n - start_ms) >= timeout_ms;
}
