# portscan

A small, dependency-free TCP port scanner: threaded, fast, and readable output with service banners.

- **Full TCP connect** scans, no admin rights or raw sockets needed
- Scan the **~90 most common ports**, all 65,535, or any list and ranges
- **Banner grabbing** for SSH, FTP, SMTP, HTTP(S) and anything else that talks first
- Identifies services by **banner as well as port number**
- Flags **ports that shouldn't be exposed**: Telnet, SMB, RDP, VNC, databases, Docker API, Redis...
- Hosts, hostnames or small **CIDR ranges**; CSV / JSON export

Python 3.8+, standard library only. Windows, macOS and Linux.

## Usage

```bash
# Common ports on one host
python portscan.py 192.168.1.10

# Every port
python portscan.py 192.168.1.10 -p all

# Specific ports across a subnet (hosts with nothing open are skipped)
python portscan.py 192.168.1.0/24 -p 22,80,443,445,3389

# Spreadsheet for the report
python portscan.py server.example.com -p 1-10000 -f csv -o ports.csv
```

### Example output

```
$ python portscan.py 192.168.1.10
[*] Scanning 1 host(s), 90 port(s) each
192.168.1.10
  PORT     SERVICE          BANNER
  22/tcp   ssh              SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
  80/tcp   http             HTTP/1.1 301 Moved Permanently | nginx/1.24.0
  445/tcp  smb
                            [!] SMB exposed (ransomware's favorite door)
  3306/tcp mysql            J...8.0.39
                            [!] Database port exposed
  8080/tcp http-proxy       HTTP/1.1 200 OK | Jetty(9.4.z)

[*] 5 open port(s) on 1 host(s) in 1.9s
```

## Options

| Flag | Description |
|---|---|
| `-p, --ports PORTS` | 'top' (default, ~90 common ports), 'all', or e.g. 22,80,443,8000-8100 |
| `-j, --threads N` | Parallel workers (default 200) |
| `-t, --timeout N` | Connect timeout in seconds (default 0.8) |
| `--no-banner` | Don't grab service banners |
| `-f, --format` | Output format (`table` / `csv` / `json`) |
| `-o, --output FILE` | Write results to a file |
| `-q, --quiet` | No progress output |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan finished, no risky ports open |
| `1` | At least one risky port is open |
| `2` | Bad input, or no target could be resolved |

## Notes

Only run it against systems and networks you own or have written permission to test. Scanning other people's networks can be illegal even when nothing is broken.

A connect scan completes the TCP handshake, so it will show up in the target's logs. That's intentional: this is a tool for checking your own systems, not for stealth.

Firewalled ports that silently drop packets take the full timeout to rule out. On a slow or distant network raise `-t`; on a LAN you can lower it to `0.3` for speed.

"Risky" means "shouldn't usually face an untrusted network". SMB on a file server inside the office is normal, SMB reachable from the internet is not.

## License

MIT, see [LICENSE](LICENSE).

---

Part of [Landull](https://github.com/Landull)'s scankit.
