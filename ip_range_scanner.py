#!/usr/bin/env python3
"""Educational private-network IP range scanner (TCP connect checks only).

Only scan networks you own or are explicitly authorised to test.
Host "reachable" means: a port accepted the connection (open) OR actively refused it
(closed). A refusal proves a machine answered. Timeouts alone are reported as "no response".
"""
import argparse
import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

DEFAULT_PORTS = [22, 80, 443, 8080]
MAX_PORTS = 10          # only a small set of ports is allowed
MAX_HOSTS_LIMIT = 256   # hard ceiling for addresses per run


def parse_network(cidr, max_hosts):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise ValueError(f"'{cidr}' is not a valid CIDR range (example: 192.168.1.0/24).") from None
    if net.version != 4:
        raise ValueError("Only IPv4 ranges are supported.")
    if not net.is_private:
        raise ValueError(f"{net} is not a private range. Only RFC 1918 / loopback ranges are allowed "
                         "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8).")
    hosts = list(net.hosts()) if net.prefixlen < 31 else list(net)
    if len(hosts) > max_hosts:
        raise ValueError(f"{net} has {len(hosts)} addresses; the limit is {max_hosts}. Use a smaller range (e.g. /24).")
    return net, hosts


def parse_ports(spec):
    try:
        ports = sorted({int(p) for p in spec.split(",") if p.strip()})
    except ValueError:
        raise ValueError("Ports must be numbers separated by commas, e.g. 22,80,443.") from None
    if not ports:
        raise ValueError("No ports given.")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"Too many ports: at most {MAX_PORTS} allowed.")
    if any(p < 1 or p > 65535 for p in ports):
        raise ValueError("Ports must be between 1 and 65535.")
    return ports


def check_port(ip, port, timeout):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return "no response"


def scan_host(ip, ports, timeout):
    states = {p: check_port(ip, p, timeout) for p in ports}
    open_ports = [p for p, s in states.items() if s == "open"]
    reachable = any(s in ("open", "closed") for s in states.values())
    return ip, reachable, open_ports


def main(argv=None):
    ap = argparse.ArgumentParser(description="Educational private IPv4 range scanner (authorised use only).")
    ap.add_argument("cidr", help="Private IPv4 range, e.g. 192.168.1.0/24")
    ap.add_argument("-p", "--ports", default=",".join(map(str, DEFAULT_PORTS)),
                    help=f"Comma-separated ports, max {MAX_PORTS} (default {','.join(map(str, DEFAULT_PORTS))})")
    ap.add_argument("-t", "--timeout", type=float, default=0.5, help="Seconds per connection (default 0.5)")
    ap.add_argument("--max-hosts", type=int, default=256, help="Address limit (default/max 256)")
    ap.add_argument("--workers", type=int, default=50, help="Hosts scanned in parallel (max 100)")
    ap.add_argument("--confirm-authorized", action="store_true",
                    help="REQUIRED: confirms you own this network or have written permission to scan it")
    args = ap.parse_args(argv)

    if not args.confirm_authorized:
        print("Refusing to run: add --confirm-authorized to confirm you own this network or have permission.")
        return 3
    if not 0.1 <= args.timeout <= 10:
        print("Error: --timeout must be between 0.1 and 10 seconds.")
        return 2
    try:
        net, hosts = parse_network(args.cidr, min(args.max_hosts, MAX_HOSTS_LIMIT))
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2

    print(f"Scanning {net} ({len(hosts)} addresses) on ports {ports}, timeout {args.timeout}s")
    start = time.time()
    workers = max(1, min(args.workers, 100))
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda h: scan_host(h, ports, args.timeout), hosts))
    except KeyboardInterrupt:
        print("\nScan cancelled.")
        return 130

    up = [(ip, op) for ip, reachable, op in results if reachable]
    print("\nHOST              OPEN PORTS")
    for ip, op in up:
        print(f"{str(ip):<17} {', '.join(map(str, op)) if op else '(none of the listed ports)'}")
    if not up:
        print("(no reachable hosts found)")
    print(f"\nDone in {time.time() - start:.2f}s: {len(up)} of {len(hosts)} addresses reachable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
