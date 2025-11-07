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
#ifndef UTIL_H
#define UTIL_H

#include <netinet/in.h> /* AF_INET/AF_INET6, sockaddr_in/in6 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h> /* socklen_t, sockaddr_storage */
#include <time.h>

/* Log-Level:
 * 0 = only errors
 * 1 = information
 * 2 = debug
 */
extern int g_log_level;

/* Simple, thread-safe (per process suffices) Logging wrapper on stderr.
 * All messages are for humans – protocol frames are parsed separately. */
void log_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_dbg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Bind an Interface (SO_BINDTODEVICE, Fallback: bind() to local IF address).
 * family: AF_INET or AF_INET6; if AF_UNSPEC, will be chosen appropriately for
 * the peer. Returns 0 on success, <0 on error. */
int net_bind_to_interface(int fd, const char *ifname, int family);

/* Get first address of an interface appropriate for family. 0 = OK */
int get_iface_addr(const char *ifname, int family, struct sockaddr_storage *sa,
                   socklen_t *salen);

/* Hex-String to binary data (PSK-Key etc.).
 * Expects e.g. "001122AABB", returns length or -1 on error. */
int hex_to_bin(const char *hex, uint8_t *out, size_t outlen);

/* Monotonic clock in milliseconds since start (CLOCK_MONOTONIC). */
uint64_t now_ms(void);

/* Timeout-Helper: true if (now_ms() - start_ms) >= timeout_ms. */
int timed_out(uint64_t start_ms, uint64_t timeout_ms);

/* Exit codes consolidated at a central place. */
enum {
  EXIT_OK = 0,
  EXIT_CLI = 1,
  EXIT_NET_HANDSHAKE = 2,
  EXIT_BROKER_PROTO = 3,
  EXIT_TIMEOUT = 4,
  EXIT_IO = 5,
  EXIT_INTERNAL = 6
};

#endif
