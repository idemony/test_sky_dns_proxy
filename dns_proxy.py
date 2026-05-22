#!/usr/bin/env python3
"""
SkyDNS DNS proxy.

Listens on 127.0.0.1:5353, adds a custom EDNS0 option with filtering token,
forwards the query to SkyDNS, logs categories from the response and returns the
upstream response to the client unchanged.
"""

from __future__ import annotations

import argparse
import logging
import re
import socket
import socketserver
from typing import Iterable

from dnslib import DNSRecord, EDNS0, EDNSOption, QTYPE

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5353
UPSTREAM_HOST = "193.58.251.251"
UPSTREAM_PORT = 53

FILTER_TOKEN_OPTION_CODE = 0xFFF0  # 65520
CATEGORIES_OPTION_CODE = 65000
DEFAULT_UDP_PAYLOAD_SIZE = 1232


def parse_filter_token(value: str) -> bytes:
    """Convert token from CLI to a 4-byte big-endian sequence.

    Accepted forms:
    - decimal integer: 123456
    - hex integer with prefix: 0x1e240
    - DoH URL with hex token: https://abcdef12.doh.skydns.ru
    - DoH URL with decimal-only token: https://123456.doh.skydns.ru
    """
    token_text = value.strip()

    url_match = re.fullmatch(
        r"https?://([0-9A-Fa-f]+)\.doh\.skydns\.ru/?",
        token_text,
        re.ASCII,
    )

    try:
        if url_match:
            token_int = int(url_match.group(1), 16)
        else:
            token_int = int(token_text, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "token must be a decimal/hex integer or a URL like https://<token>.doh.skydns.ru"
        ) from exc

    if not 0 <= token_int <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("token must fit into 4 bytes: 0..4294967295")

    return token_int.to_bytes(4, byteorder="big", signed=False)


def add_filter_token_option(packet: bytes, token: bytes) -> bytes:
    """Add EDNS0 option 65520 with the filtering token to the DNS query.

    If the client already sent an OPT record, preserve its UDP payload size and
    EDNS flags/version while appending the custom option. This avoids changing
    client-requested EDNS behavior such as DNSSEC DO bit.
    """
    request = DNSRecord.parse(packet)
    option = EDNSOption(FILTER_TOKEN_OPTION_CODE, token)

    existing_options = []
    udp_len = DEFAULT_UDP_PAYLOAD_SIZE
    ttl = 0

    for additional_record in list(request.ar):
        if additional_record.rtype != QTYPE.OPT:
            continue

        udp_len = getattr(additional_record, "rclass", udp_len)
        ttl = getattr(additional_record, "ttl", ttl)
        existing_options.extend(additional_record.rdata)
        request.ar.remove(additional_record)

    existing_options = [
        existing_option
        for existing_option in existing_options
        if getattr(existing_option, "code", None) != FILTER_TOKEN_OPTION_CODE
    ]
    existing_options.append(option)

    opt_record = EDNS0(
        udp_len=udp_len,
        opts=existing_options,
    )
    opt_record.ttl = ttl
    request.add_ar(opt_record)

    return request.pack()


def iter_response_categories(packet: bytes) -> Iterable[list[int]]:
    """Yield valid 8-byte category lists from EDNS0 option 65000 in the response."""
    response = DNSRecord.parse(packet)

    for additional_record in response.ar:
        if additional_record.rtype != QTYPE.OPT:
            continue

        for option in additional_record.rdata:
            if getattr(option, "code", None) != CATEGORIES_OPTION_CODE:
                continue

            data = bytes(option.data)
            if len(data) != 8:
                logging.warning("Invalid categories length: %d, raw=%r", len(data), data)
                continue

            yield list(data)


class DNSProxyHandler(socketserver.BaseRequestHandler):
    """UDP request handler; server attributes are set in main()."""

    def handle(self) -> None:
        client_packet, client_socket = self.request
        client_ip, client_port = self.client_address

        if len(client_packet) > 4096:
            logging.warning("Client packet too large: %d", len(client_packet))
            return

        logging.info(
            "Received %d bytes from %s:%s",
            len(client_packet),
            client_ip,
            client_port,
        )

        try:
            proxied_packet = add_filter_token_option(client_packet, self.server.filter_token)
        except Exception:
            logging.exception("Failed to parse/modify DNS query from %s:%s", client_ip, client_port)
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
                upstream_socket.settimeout(self.server.timeout)
                upstream_socket.sendto(proxied_packet, self.server.upstream)
                response_packet, _ = upstream_socket.recvfrom(65535)
        except socket.timeout:
            logging.warning("Upstream DNS timeout for client %s:%s", client_ip, client_port)
            return
        except OSError:
            logging.exception("Failed to query upstream DNS server")
            return

        try:
            found_categories = False
            for categories in iter_response_categories(response_packet):
                found_categories = True
                logging.info("Categories: %s", categories)

            if not found_categories:
                logging.info("Categories: not found in response")
        except Exception:
            logging.exception("Failed to parse categories from upstream response")

        client_socket.sendto(response_packet, self.client_address)


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SkyDNS DNS proxy with custom EDNS0 options")
    parser.add_argument(
        "--token",
        required=True,
        type=parse_filter_token,
        help="filtering token: decimal/hex integer or https://<token>.doh.skydns.ru",
    )
    parser.add_argument("--listen-host", default=LISTEN_HOST)
    parser.add_argument("--listen-port", type=int, default=LISTEN_PORT)
    parser.add_argument("--upstream-host", default=UPSTREAM_HOST)
    parser.add_argument("--upstream-port", type=int, default=UPSTREAM_PORT)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--debug", action="store_true")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    server_address = (args.listen_host, args.listen_port)
    upstream_address = (args.upstream_host, args.upstream_port)

    with ThreadingUDPServer(server_address, DNSProxyHandler) as server:
        server.filter_token = args.token
        server.upstream = upstream_address
        server.timeout = args.timeout

        logging.info("Listening on %s:%s", *server_address)
        logging.info("Forwarding DNS queries to %s:%s", *upstream_address)
        server.serve_forever()


if __name__ == "__main__":
    main()