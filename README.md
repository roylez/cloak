# Cloak

A multi-user Shadowsocks/Trojan implementation in Elixir. For best performance, use it with Erlang/OTP 20 or newer.

## Features

* Shadowsocks stream/AEAD ciphers, TCP and UDP
* Trojan protocol
* Multi-user
* Users can be defined both in yaml file and by MQTT messages
* Usage data via MQTT
* DNS cache

## Shadowsocks Ciphers

* aes-128-ctr (stream, **DO NOT USE**)
* aes-192-ctr (stream, **DO NOT USE**)
* aes-256-ctr (stream, **DO NOT USE**)
* aes-128-cfb (stream, **DO NOT USE**)
* aes-192-cfb (stream, **DO NOT USE**)
* aes-256-cfb (stream, **DO NOT USE**)
* aes-128-gcm (AEAD)
* aes-256-gcm (AEAD)
* 2022-blake3-aes-256-gcm (Shadowsocks 2022 AEAD)

## Environment Variables

```
ERLANG_COOKIE: # Erlang node cookie, better to change it to a random secret, default: CHANGEME
HOST:          # Erlang node hostname, just in case it does not detect it correctly   

CLOAK_ENABLE_STATIC: # If accounts in /etc/cloak.yaml should be read, default: 1
CLOAK_ENABLE_MQTT:   # If MQTT account management should be enabled, default: 0
CLOAK_ENABLE_TROJAN: # If Trojan should be enabled, default: 0

CLOAK_MQTT_HOST:        # MQTT server address, default: localhost
CLOAK_MQTT_CLIENT:      # MQTT client id
CLOAK_MQTT_USERNAME:    # MQTT username, default: cloak
CLOAK_MQTT_PASSWORD:    # MQTT password, default: cloak

CLOAK_TROJAN_PORT:        # Port to listen for trojan requests, default: 2000
CLOAK_TROJAN_CACERT:      # trojan ca chain cert, default: "./ssl/chain.pem"
CLOAK_TROJAN_CERT:        # trojan server cert, default: "./ssl/cert.pem"
CLOAK_TROJAN_KEY:         # trojan server key, default: "./ssl/privkey.pem"
CLOAK_TROJAN_FAKE_SEVER:  # trojan fake http server, default: "127.0.0.1"
CLOAK_TROJAN_FAKE_SEVER_PORT:  # trojan fake http server port, default: 80
```

## Manual Installation

On deployment machine. run the following.

    mix deps.get
    MIX_ENV=prod mix release
    _build/prod/rel/cloak/bin/cloak start

## Docker Deployment

With docker-compose. Here `network_mode: host` is used to make it easier to expose a large range of ports.

```
version: '3.6'

services:
  ss:
    image: roylez/cloak
    network_mode: host
    restart: always
    volumes:
      - ./cloak.yml:/etc/cloak.yml
```

Static accounts can be written in the following `cloak.yml`

``` yaml
---

- port: 4444
  passwd: aaaaaa
  method: aes-256-gcm
- port: 4445
  # passwd can be generated with
  # openssl rand -base64 32
  passwd: q7Dut5M/e93LytgPOMhIAxn485l9QemAr4jPAVAiWUk=
  method: 2022-blake3-aes-256-gcm
```

## FAQ

1. How good is it at avoiding detection?

Pretty good. It has been running in production for more than 3 years and there is no history of being obviously detected even when some of the users are still using chacha20.

2. Does it support tcp fast open?

No. TCP fast open requires a TFO cookie within all packages sent, and this may lead to leaking of information about the client. [The Sad Story of TCP fast open][1] may be an interesting read.

3. Aren't those stream ciphers insecure because of their design flaw against replay attack?

Yes. It looks like the wall is getting better at active pattern detection and replay attacks. Use an AEAD or Shadowsocks 2022 AEAD cipher instead.

4. Why there is no obfucscation function?

Vanilla Shadowsocks is good enough and I do not see any point adding this.

5. How about Trojan? How does it perform?

It is a simple idea that works great, but deployment is trickier. I have not tested its performance versus shadowsocks. However I may remove it later if the new Quanzhou DNS whitelisting becomes mainstream.

[1]: https://squeeze.isobar.com/2019/04/11/the-sad-story-of-tcp-fast-open/
