#!/usr/bin/env python3
"""
portscan - fast threaded TCP connect scanner with service banners.

Scans one host, a list of hosts or a small CIDR range for open TCP
ports, names the likely service, grabs a banner where the service
volunteers one (SSH, FTP, SMTP, HTTP and friends), and flags ports that
shouldn't usually be exposed (Telnet, SMB, RDP, databases, etc.).

Uses full TCP connects, so it needs no admin rights and no raw sockets.
Only scan systems you own or are authorized to test.

Standard library only. Python 3.8+.
"""

import argparse
import csv
import ipaddress
import json
import socket
import ssl
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

__version__ = "1.0.0"

# Roughly the most commonly open TCP ports on real networks
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 514, 548, 587,
    631, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2375,
    2376, 3000, 3128, 3268, 3306, 3389, 4443, 4848, 5000, 5001, 5060, 5222, 5353, 5357, 5432,
    5601, 5672, 5900, 5985, 5986, 6379, 6443, 7001, 7070, 8000, 8008, 8009, 8080, 8081, 8088,
    8089, 8123, 8181, 8443, 8834, 8888, 9000, 9042, 9090, 9100, 9200, 9300, 9443, 10000, 11211,
    15672, 25565, 27017, 32400, 49152, 50000,
]

NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http-alt", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "rsh/syslog", 548: "afp", 587: "submission", 631: "ipp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2181: "zookeeper", 2375: "docker", 2376: "docker-tls", 3000: "http-dev", 3128: "squid",
    3268: "globalcatalog", 3306: "mysql", 3389: "rdp", 4443: "https-alt", 4848: "glassfish",
    5000: "http-alt/upnp", 5001: "synology", 5060: "sip", 5222: "xmpp", 5353: "mdns", 5357: "wsdapi",
    5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-https",
    6379: "redis", 6443: "kubernetes", 7001: "weblogic", 7070: "http-alt", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp", 8080: "http-proxy", 8081: "http-alt", 8088: "http-alt",
    8089: "splunk", 8123: "home-assistant", 8181: "http-alt", 8443: "https-alt", 8834: "nessus",
    8888: "http-alt", 9000: "http-alt", 9042: "cassandra", 9090: "http-alt", 9100: "jetdirect",
    9200: "elasticsearch", 9300: "elasticsearch", 9443: "https-alt", 10000: "webmin",
    11211: "memcached", 15672: "rabbitmq", 25565: "minecraft", 27017: "mongodb", 32400: "plex",
    49152: "upnp", 50000: "sap/db2",
}

RISKY = {
    21: "FTP sends credentials in clear text",
    23: "Telnet sends everything in clear text",
    135: "MS RPC shouldn't face untrusted networks",
    139: "NetBIOS shouldn't face untrusted networks",
    445: "SMB exposed (ransomware's favorite door)",
    1433: "Database port exposed", 1521: "Database port exposed", 3306: "Database port exposed",
    5432: "Database port exposed", 27017: "Database port exposed", 9042: "Database port exposed",
    2375: "Docker API without TLS = root on the host",
    3389: "RDP exposed; put it behind a VPN",
    5900: "VNC exposed; often weakly authenticated",
    5985: "WinRM over HTTP",
    6379: "Redis often has no authentication",
    9200: "Elasticsearch often has no authentication",
    11211: "Memcached can be abused for DDoS amplification",
    1723: "PPTP VPN is cryptographically broken",
    512: "rexec sends credentials in clear text", 513: "rlogin sends credentials in clear text",
}

TLS_PORTS = {443, 465, 636, 993, 995, 2083, 4443, 5986, 6443, 8443, 9443, 2376, 8834}
HTTP_PORTS = {80, 81, 3000, 5000, 7070, 8000, 8008, 8080, 8081, 8088, 8181, 8888, 9000, 9090, 10000, 8123}


def parse_ports(spec):
    if spec in ("top", None):
        return list(TOP_PORTS)
    if spec in ("all", "-"):
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a or 1), int(b or 65535)
            if not (1 <= a <= b <= 65535):
                raise ValueError(f"bad range {part}")
            ports.update(range(a, b + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f"bad port {p}")
            ports.add(p)
    return sorted(ports)


def parse_targets(items):
    hosts = []
    for item in items:
        try:
            net = ipaddress.ip_network(item, strict=False)
            if net.num_addresses > 1:
                if net.num_addresses > 1024:
                    raise ValueError(f"{item} is larger than /22; narrow it down")
                hosts.extend(str(h) for h in net.hosts())
                continue
            hosts.append(str(net.network_address))
        except ValueError as err:
            if "larger than" in str(err):
                raise
            hosts.append(item)  # hostname
    return hosts


def service_name(port):
    if port in NAMES:
        return NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def grab_banner(ip, host, port, timeout):
    """Read whatever the service says first; nudge HTTP(S) with a HEAD request."""
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return ""
    try:
        sock = raw
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(raw, server_hostname=host if not host[0].isdigit() else None)
            except (ssl.SSLError, OSError):
                return "(TLS handshake failed)"
        sock.settimeout(timeout)
        data = b""
        try:
            data = sock.recv(512)
        except (socket.timeout, OSError):
            pass
        if not data and (port in HTTP_PORTS or port in TLS_PORTS):
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: portscan\r\n\r\n".encode())
            try:
                data = sock.recv(1024)
            except (socket.timeout, OSError):
                pass
        return summarize_banner(data)
    finally:
        try:
            raw.close()
        except OSError:
            pass


def summarize_banner(data):
    text = data.decode("utf-8", "replace")
    if text.startswith("HTTP/"):
        status = text.splitlines()[0]
        server = next((l.split(":", 1)[1].strip() for l in text.splitlines()
                       if l.lower().startswith("server:")), "")
        return f"{status}" + (f" | {server}" if server else "")
    line = text.strip().splitlines()[0] if text.strip() else ""
    return "".join(c if c.isprintable() else "." for c in line)[:100]


def check(ip, port, timeout):
    s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return port if s.connect_ex((ip, port)) == 0 else None
    except OSError:
        return None
    finally:
        s.close()


def scan_host(host, ports, threads, timeout, banners, quiet):
    try:
        ip = socket.getaddrinfo(host, None)[0][4][0]
    except socket.gaierror as err:
        return {"host": host, "error": f"can't resolve ({err.strerror})"}
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(check, ip, p, timeout) for p in ports]
        done = 0
        for fut in as_completed(futures):
            done += 1
            if fut.result():
                open_ports.append(fut.result())
            if not quiet and sys.stderr.isatty() and len(ports) > 2000 and done % 500 == 0:
                print(f"\r[*] {host}: {done}/{len(ports)}", end="", file=sys.stderr)
    if not quiet and sys.stderr.isatty() and len(ports) > 2000:
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr)

    results = []
    open_ports.sort()
    with ThreadPoolExecutor(max_workers=min(16, len(open_ports) or 1)) as pool:
        banner_list = list(pool.map(lambda p: grab_banner(ip, host, p, max(timeout, 2)) if banners else "",
                                    open_ports))
    for port, banner in zip(open_ports, banner_list):
        service = service_name(port)
        # The banner beats the port number when a service runs somewhere unusual
        if banner.startswith("SSH-"):
            service = "ssh"
        elif banner.startswith("HTTP/") and "http" not in service:
            service = "https" if port in TLS_PORTS else "http"
        elif banner.startswith("220") and not service:
            service = "ftp" if "ftp" in banner.lower() else "smtp" if "smtp" in banner.lower() else service
        results.append({"port": port, "service": service, "banner": banner,
                        "risk": RISKY.get(port, "")})
    return {"host": host, "ip": ip, "open": results}


def print_host(rec, total_ports):
    label = rec["host"] if rec.get("ip") in (None, rec["host"]) else f"{rec['host']} ({rec['ip']})"
    print(label)
    if "error" in rec:
        print(f"  [!] {rec['error']}")
        return
    if not rec["open"]:
        print(f"  no open ports among {total_ports} scanned")
        return
    print(f"  {'PORT':<8} {'SERVICE':<16} BANNER")
    for p in rec["open"]:
        print(f"  {str(p['port']) + '/tcp':<8} {p['service'][:16]:<16} {p['banner']}")
        if p["risk"]:
            print(f"  {'':<8} {'':<16} [!] {p['risk']}")


def parse_args(argv):
    p = argparse.ArgumentParser(prog="portscan", description="Threaded TCP connect scanner with service banners.")
    p.add_argument("targets", nargs="+", help="host, IP or CIDR (up to /22)")
    p.add_argument("-p", "--ports", default="top",
                   help="'top' (default, ~90 common ports), 'all', or e.g. 22,80,443,8000-8100")
    p.add_argument("-j", "--threads", type=int, default=200, help="parallel workers (default 200)")
    p.add_argument("-t", "--timeout", type=float, default=0.8, help="connect timeout in seconds (default 0.8)")
    p.add_argument("--no-banner", action="store_true", help="don't grab service banners")
    p.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table", help="output format")
    p.add_argument("-o", "--output", metavar="FILE", help="write results to a file")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        ports = parse_ports(args.ports)
        hosts = parse_targets(args.targets)
    except ValueError as err:
        print(f"[!] {err}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(f"[*] Scanning {len(hosts)} host(s), {len(ports)} port(s) each", file=sys.stderr)
    started = time.time()
    records = []
    for host in hosts:
        rec = scan_host(host, ports, args.threads, args.timeout, not args.no_banner, args.quiet)
        # In range scans, skip hosts with nothing open
        if len(hosts) > 1 and not rec.get("open") and "error" not in rec:
            continue
        records.append(rec)
        if args.format == "table" and not args.output:
            if len(records) > 1:
                print()
            print_host(rec, len(ports))
    elapsed = time.time() - started

    if args.format == "csv":
        fh = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
        w = csv.writer(fh)
        w.writerow(["host", "ip", "port", "service", "banner", "risk"])
        for r in records:
            for p in r.get("open", []):
                w.writerow([r["host"], r.get("ip"), p["port"], p["service"], p["banner"], p["risk"]])
        if args.output:
            fh.close()
    elif args.format == "json" or args.output:
        data = json.dumps({"scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           "ports_scanned": len(ports), "hosts": records}, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(data + "\n")
        else:
            print(data)
    if args.output and not args.quiet:
        print(f"[*] Wrote {args.output}", file=sys.stderr)

    total_open = sum(len(r.get("open", [])) for r in records)
    if not args.quiet:
        print(f"\n[*] {total_open} open port(s) on {sum(1 for r in records if r.get('open'))} host(s) "
              f"in {elapsed:.1f}s", file=sys.stderr)
    if records and all("error" in r for r in records):
        return 2
    return 1 if any(p["risk"] for r in records for p in r.get("open", [])) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:  # e.g. piped into `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
