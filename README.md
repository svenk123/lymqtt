# MQTT and MQTT-SN Command Line Clients for Linux

This project provides lightweight command-line tools for MQTT and MQTT-SN communication on Linux systems. The tools are designed to be simple, memory-efficient, and suitable for embedded systems.

## Overview

The package includes the following command-line programs:

- **`mqtt_pub`** - MQTT publisher client (TCP/TLS)
- **`mqtt_sub`** - MQTT subscriber client (TCP/TLS)
- **`mqttsn_pub`** - MQTT-SN publisher client (UDP/DTLS)
- **`mqttsn_sub`** - MQTT-SN subscriber client (UDP/DTLS)

## Features

- **Simple Implementation**: Minimalist design focused on essential MQTT/MQTT-SN functionality
- **Memory Efficient**: Optimized for embedded systems with limited resources
- **Security Support**: 
  - TLS encryption for MQTT (TCP-based)
  - DTLS encryption for MQTT-SN (UDP-based)
  - Supports both PSK (Pre-Shared Key) and X.509 certificate authentication
- **Multiple Topics**: Subscriber clients can subscribe to multiple topics simultaneously
- **Topic Identification**: Received messages include the topic name for easy parsing
- **Cross-Platform**: Can be cross-compiled for various architectures (e.g., MIPS)

## Dependencies

- **mbedTLS**: External SSL/TLS library used for cryptographic operations
- **GCC**: C compiler (C11 standard)
- **GNU Make**: Build system

## Building

### Step 1: Download and Build mbedTLS

1. Download mbedTLS (version 2.16.1 or compatible):
   ```bash
   cd ..
   wget https://github.com/Mbed-TLS/mbedtls/archive/v2.16.1.tar.gz
   tar xzf v2.16.1.tar.gz
   mv mbedtls-2.16.1 mbedtls-2.16.1_lymqtt
   cd mbedtls-2.16.1_lymqtt
   ```

2. Copy the provided configuration file:
   ```bash
   cp ../lymqtt/mbedtls_config.h include/mbedtls/config.h
   ```

3. Build mbedTLS:
   ```bash
   make
   ```

   This will create the mbedTLS libraries in the `library/` directory.

### Step 2: Build the MQTT Clients

1. Navigate to the project directory:
   ```bash
   cd ../lymqtt
   ```

2. Build all clients:
   ```bash
   make
   ```

   The compiled binaries will be created in the project root:
   - `mqtt_pub`
   - `mqtt_sub`
   - `mqttsn_pub`
   - `mqttsn_sub`

### Cross-Compilation

To cross-compile for a different architecture (e.g., MIPS), set the `CROSS_COMPILE` variable:

```bash
make CROSS_COMPILE=mipsel-linux-musl-
```

## Usage Examples

### MQTT Publisher

Publish a message to a topic:
```bash
mqtt_pub --host broker.example.com --port 1883 --client-id myclient \
         --topic sensor/temperature --message "25.3"
```

Publish with TLS and PSK authentication:
```bash
mqtt_pub --host broker.example.com --port 8883 --client-id myclient \
         --topic sensor/temperature --message "25.3" \
         --tls --psk-identity "client1" --psk-key "00112233445566778899aabbccddeeff"
```

Publish with TLS and X.509 certificates:
```bash
mqtt_pub --host broker.example.com --port 8883 --client-id myclient \
         --topic sensor/temperature --message "25.3" \
         --tls --ca ca.crt --cert client.crt --key client.key
```

### MQTT Subscriber

Subscribe to a single topic:
```bash
mqtt_sub --host broker.example.com --port 1883 --client-id myclient \
         --topic sensor/temperature
```

Subscribe to multiple topics:
```bash
mqtt_sub --host broker.example.com --port 1883 --client-id myclient \
         --topic sensor/temperature --topic sensor/humidity --topic sensor/pressure
```

Subscribe with TLS and username/password:
```bash
mqtt_sub --host broker.example.com --port 8883 --client-id myclient \
         --topic sensor/temperature --tls \
         --username myuser --password mypass
```

Output format: Each received message is printed as `TOPIC: MESSAGE` on a new line:
```
sensor/temperature: 25.3
sensor/humidity: 60.2
sensor/pressure: 1013.25
```

### MQTT-SN Publisher

Publish a message via MQTT-SN (UDP):
```bash
mqttsn_pub --host gateway.example.com --port 1884 --client-id myclient \
           --interface eth0 --topic sensor/temperature --message "25.3"
```

Publish with DTLS and PSK:
```bash
mqttsn_pub --host gateway.example.com --port 1884 --client-id myclient \
           --interface eth0 --topic sensor/temperature --message "25.3" \
           --dtls --psk-identity "client1" --psk-key "00112233445566778899aabbccddeeff"
```

Publish using a predefined topic ID:
```bash
mqttsn_pub --host gateway.example.com --port 1884 --client-id myclient \
           --interface eth0 --topic-id 1 --message "25.3"
```

### MQTT-SN Subscriber

Subscribe to a topic:
```bash
mqttsn_sub --host gateway.example.com --port 1884 --client-id myclient \
           --interface eth0 --topic sensor/temperature
```

Subscribe to multiple topics:
```bash
mqttsn_sub --host gateway.example.com --port 1884 --client-id myclient \
           --interface eth0 --topic sensor/temperature --topic sensor/humidity
```

Subscribe with DTLS:
```bash
mqttsn_sub --host gateway.example.com --port 1884 --client-id myclient \
           --interface eth0 --topic sensor/temperature \
           --dtls --psk-identity "client1" --psk-key "00112233445566778899aabbccddeeff"
```

Output format: Each received message is printed as `TOPIC: MESSAGE` on a new line.

## Common Options

- `--host HOST` - Broker/gateway hostname or IP address
- `--port PORT` - Port number (default: 1884 for MQTT-SN, 1883 for MQTT)
- `--client-id ID` - Client identifier (required)
- `--interface IFACE` - Network interface to bind to (required for MQTT-SN)
- `--topic NAME` - Topic name (can be specified multiple times for subscribers)
- `--topic-id N` - Predefined topic ID (MQTT-SN only)
- `--qos LEVEL` - Quality of Service level (-1, 0, or 1)
- `--keepalive SEC` - Keep-alive interval in seconds
- `--timeout SEC` - Operation timeout in seconds
- `--recv-timeout SEC` - Receive timeout for subscribers
- `--tls` - Enable TLS encryption (MQTT only)
- `--dtls` - Enable DTLS encryption (MQTT-SN only)
- `--psk-identity ID` - PSK identity
- `--psk-key HEX` - PSK key in hexadecimal format
- `--ca PATH` - CA certificate file path
- `--cert PATH` - Client certificate file path
- `--key PATH` - Client private key file path
- `--username USER` - Username for authentication (MQTT only)
- `--password PASS` - Password for authentication (MQTT only)
- `--verbose` - Enable verbose logging
- `--help` - Show usage information

## License

See LICENSE.md for details.
