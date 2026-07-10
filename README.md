# UPing

`UPing` means **USTPS-Ping**.

It is a ping-like tool built on top of **USTP-Secure**.

## What it does

- uses `USTPS` as the transport
- server listens on port `40002` by default
- client sends ping frames and measures RTT over the secure transport
- supports stable `USTP/1.1` and optional `USTP/2 Beta`

## Address family behavior

- `-6`: force IPv6
- `-4`: force IPv4
- with neither flag:
  - try IPv6 first
  - if IPv6 times out or errors, fall back to IPv4

## Files

- `server.py`
- `client.py`
- `uping_proto.py`
- `aead_udp.py`
- `packet.py`
- `ustp.py`

## Server

```bash
python3 server.py
```

If `systemd` is available and you run it as `root`, running without `--start` installs/updates the unit and exits.

Foreground run:

```bash
python3 server.py --start
```

Custom bind:

```bash
python3 server.py --bind-ip 0.0.0.0 --bind-port 40002
```

Simulated loss:

```bash
python3 server.py --start --loss 30
```

Force congestion control on:

```bash
python3 server.py --start --congestion-control on
```

Allow negotiated cleartext + HMAC mode:

```bash
python3 server.py --start --cleartext auto
```

Allow negotiated `USTP/2 Beta`:

```bash
python3 server.py --start --ustp2beta auto
```

## Client

Default:

```bash
python3 client.py --peer-ip x1co.com.br
```

Force IPv6:

```bash
python3 client.py -6 --peer-ip x1co.com.br
```

Force IPv4:

```bash
python3 client.py -4 --peer-ip x1co.com.br
```

Infinite ping:

```bash
python3 client.py --peer-ip x1co.com.br
```

Custom interval and timeout:

```bash
python3 client.py --peer-ip x1co.com.br -i 1.0 -W 3.0
```

Request congestion control:

```bash
python3 client.py --peer-ip x1co.com.br --congestion-control on
```

Request cleartext + HMAC mode:

```bash
python3 client.py --peer-ip x1co.com.br --cleartext on
```

Request `USTP/2 Beta`:

```bash
python3 client.py --peer-ip x1co.com.br --ustp2beta on
```

Test `USTP/1.1` and `USTP/2 Beta` simultaneously:

```bash
python3 client.py --peer-ip x1co.com.br --test-ustp2beta-and-ustp1.1-simultaneously
```

## Notes

- this uses `USTPS`, not raw ICMP
- TOFU is enabled on the client
- default client/server cipher is `chacha20`
- client now negotiates `--congestion-control on|off`
- client now negotiates `--cleartext on|off`
- client can negotiate `--ustp2beta on|off`
- `--test-ustp2beta-and-ustp1.1-simultaneously` opens two sessions at the same time:
  - one stable `USTP/1.1`
  - one `USTP/2 Beta`
- in `USTP/2 Beta`, the client still keeps transport semantics unordered and selective-retransmit, but it opens:
  - one socket for control packets
  - one socket for inbound `DATA`
- the tool measures RTT of the whole `USTPS` path, not bare UDP alone
- the client output is intentionally ping-like, but it reports `USTPS` session information instead of ICMP fields
- `--loss` simulates outbound packet loss on the server side for testing
