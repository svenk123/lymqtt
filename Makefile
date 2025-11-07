# Minimalistisches GNU Makefile für mqttsn_* und mqtt_* (TCP+TLS)
# Cross-Compile:  make CROSS_COMPILE=mipsel-linux-musl-
# Statischer Build: make STATIC=1
# Install:       make install PREFIX=/usr/local [DESTDIR=/path]

# -------------------------------------------------------------------
# Pfade / Tools
# -------------------------------------------------------------------
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

CROSS_COMPILE=mipsel-openwrt-linux-musl-
CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
STRIP=$(CROSS_COMPILE)strip

SRC_DIR=src
INC_DIR=include
OBJ_DIR=build

# -------------------------------------------------------------------
# Flags
# -------------------------------------------------------------------
CFLAGS  ?= -O2
CFLAGS  += -g -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align \
           -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter \
           -std=c11 -D_POSIX_C_SOURCE=200809L

LDFLAGS ?=
LIBS    ?=

# mbedTLS via pkg-config (bevorzugt)
#MBEDTLS_CFLAGS := $(shell pkg-config --cflags mbedtls 2>/dev/null)
#MBEDTLS_LIBS   := $(shell pkg-config --libs   mbedtls 2>/dev/null)

ifeq ($(MBEDTLS_LIBS),)
# Fallback, falls pkg-config fehlt – ggf. anpassen:
MBEDTLSDIR=../mbedtls-2.16.1_lymqtt
MBEDTLS_CFLAGS += -I$(MBEDTLSDIR)/include
MBEDTLS_LIBS   += -lmbedtls -lmbedx509 -lmbedcrypto
LDFLAGS += -L$(MBEDTLSDIR)/library
endif

# Statisch linken (falls Deine Toolchain das unterstützt)
ifeq ($(STATIC),1)
LDFLAGS += -static
endif

# -------------------------------------------------------------------
# Quellen
# -------------------------------------------------------------------
# Gemeinsame Utilities (wiederverwendet)
SRCS_COMMON := \
  $(SRC_DIR)/util.c \
  $(SRC_DIR)/cli.c

# MQTT-SN Kern
SRCS_MQTTSN_CORE := \
  $(SRC_DIR)/mqttsn_common.c \
  $(SRC_DIR)/mqttsn_dtls.c \
  $(SRC_DIR)/mqttsn_client.c

# MQTT-SN Frontends
SRCS_MQTTSN_PUB := $(SRC_DIR)/mqttsn_pub.c
SRCS_MQTTSN_SUB := $(SRC_DIR)/mqttsn_sub.c

# MQTT (TCP/TLS) Kern
SRCS_MQTT_CORE := \
  $(SRC_DIR)/mqtt_proto.c \
  $(SRC_DIR)/mqtt_client.c \
  $(SRC_DIR)/mqtt_tls.c

# MQTT (TCP/TLS) Frontends
SRCS_MQTT_PUB := $(SRC_DIR)/mqtt_pub.c
SRCS_MQTT_SUB := $(SRC_DIR)/mqtt_sub.c

# Objekte
OBJS_COMMON        := $(SRCS_COMMON:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
OBJS_MQTTSN_CORE   := $(SRCS_MQTTSN_CORE:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
OBJS_MQTTSN_PUB    := $(OBJ_DIR)/mqttsn_pub.o
OBJS_MQTTSN_SUB    := $(OBJ_DIR)/mqttsn_sub.o
OBJS_MQTT_CORE     := $(SRCS_MQTT_CORE:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
OBJS_MQTT_PUB      := $(OBJ_DIR)/mqtt_pub.o
OBJS_MQTT_SUB      := $(OBJ_DIR)/mqtt_sub.o

# Ziele
BIN_MQTTSN := mqttsn_pub mqttsn_sub
BIN_MQTT   := mqtt_pub mqtt_sub
BIN_ALL    := $(BIN_MQTTSN) $(BIN_MQTT)

# Includes
INCLUDES := -I$(INC_DIR) -I$(SRC_DIR) $(MBEDTLS_CFLAGS)

# -------------------------------------------------------------------
# Phony
# -------------------------------------------------------------------
.PHONY: all clean install uninstall

# -------------------------------------------------------------------
# Default
# -------------------------------------------------------------------
all: $(BIN_ALL)

# -------------------------------------------------------------------
# Build-Regeln
# -------------------------------------------------------------------
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

# Generische Compile-Regel
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ---------------- MQTT-SN Binaries ----------------
mqttsn_pub: $(OBJS_COMMON) $(OBJS_MQTTSN_CORE) $(OBJS_MQTTSN_PUB)
	$(CC) $(LDFLAGS) $^ -o $@ $(MBEDTLS_LIBS) $(LIBS)

mqttsn_sub: $(OBJS_COMMON) $(OBJS_MQTTSN_CORE) $(OBJS_MQTTSN_SUB)
	$(CC) $(LDFLAGS) $^ -o $@ $(MBEDTLS_LIBS) $(LIBS)

# ----------------  MQTT (TCP/TLS) Binaries --------
mqtt_pub: $(OBJS_COMMON) $(OBJS_MQTT_CORE) $(OBJS_MQTT_PUB)
	$(CC) $(LDFLAGS) $^ -o $@ $(MBEDTLS_LIBS) $(LIBS)

mqtt_sub: $(OBJS_COMMON) $(OBJS_MQTT_CORE) $(OBJS_MQTT_SUB)
	$(CC) $(LDFLAGS) $^ -o $@ $(MBEDTLS_LIBS) $(LIBS)

# -------------------------------------------------------------------
# Install / Uninstall
# -------------------------------------------------------------------
install: all
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 mqttsn_pub "$(DESTDIR)$(BINDIR)/mqttsn_pub"
	install -m 0755 mqttsn_sub "$(DESTDIR)$(BINDIR)/mqttsn_sub"
	install -m 0755 mqtt_pub    "$(DESTDIR)$(BINDIR)/mqtt_pub"
	install -m 0755 mqtt_sub    "$(DESTDIR)$(BINDIR)/mqtt_sub"
ifneq ($(INSTALL_STRIP),)
	$(STRIP) "$(DESTDIR)$(BINDIR)/mqttsn_pub" || true
	$(STRIP) "$(DESTDIR)$(BINDIR)/mqttsn_sub" || true
	$(STRIP) "$(DESTDIR)$(BINDIR)/mqtt_pub"    || true
	$(STRIP) "$(DESTDIR)$(BINDIR)/mqtt_sub"    || true
endif

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/mqttsn_pub" \
	      "$(DESTDIR)$(BINDIR)/mqttsn_sub" \
	      "$(DESTDIR)$(BINDIR)/mqtt_pub" \
	      "$(DESTDIR)$(BINDIR)/mqtt_sub"

# -------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------
clean:
	rm -rf $(OBJ_DIR) \
	       $(BIN_ALL)
