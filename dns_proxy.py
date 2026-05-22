#!/usr/bin/env python3
"""
SkyDNS DNS proxy.

Listens on 127.0.0.1:5353, adds a custom EDNS0 option with filtering token,
forwards the query to SkyDNS, logs categories from the response and returns the
upstream response to the client unchanged.
"""

from __future__ import annotations

import logging
import os
import socket
import socketserver
from typing import Iterable

from dnslib import DNSRecord, EDNS0, EDNSOption, QTYPE

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5353

UPSTREAM_HOST = "193.58.251.251"
UPSTREAM_PORT = 53

UPSTREAM_TIMEOUT = 3.0

FILTER_TOKEN_OPTION_CODE = 0xFFF0  # 65520
CATEGORIES_OPTION_CODE = 65000
DEFAULT_UDP_PAYLOAD_SIZE = 1232


def read_filter_token_from_env() -> bytes:
    token_text = os.environ.get("SKYDNS_TOKEN")

    if not token_text:
        raise RuntimeError("SKYDNS_TOKEN environment variable is required")

    token_int = int(token_text, 0)

    if not 0 <= token_int <= 0xFFFFFFFF:
        raise RuntimeError("SKYDNS_TOKEN must fit into 4 bytes: 0..4294967295")

    return token_int.to_bytes(4, byteorder="big", signed=False)


def add_filter_token_option(packet: bytes, token: bytes) -> bytes:
    """Add EDNS0 option 65520 with the filtering token to the DNS query."""
    request = DNSRecord.parse(packet)
    option = EDNSOption(FILTER_TOKEN_OPTION_CODE, token)

    for additional_record in request.ar:
        if additional_record.rtype == QTYPE.OPT:
            additional_record.rdata.append(option)
            break
    else:
        request.add_ar(
            EDNS0(
                udp_len=DEFAULT_UDP_PAYLOAD_SIZE,
                opts=[option],
            )
        )

    return request.pack()


def iter_response_categories(packet: bytes) -> Iterable[list[int]]:
    """Yield category lists from EDNS0 option 65000 in the DNS response."""
    response = DNSRecord.parse(packet)

    for additional_record in response.ar:
        if additional_record.rtype != QTYPE.OPT:
            continue

        for option in additional_record.rdata:
            if getattr(option, "code", None) == CATEGORIES_OPTION_CODE:
                yield list(bytes(option.data))


class DNSProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client_packet, client_socket = self.request
        client_ip, client_port = self.client_address

        try:
            proxied_packet = add_filter_token_option(client_packet, self.server.filter_token)
        except Exception:
            logging.exception("Failed to parse/modify DNS query from %s:%s", client_ip, client_port)
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
                upstream_socket.settimeout(UPSTREAM_TIMEOUT)
                upstream_socket.sendto(proxied_packet, (UPSTREAM_HOST, UPSTREAM_PORT))
                response_packet, _ = upstream_socket.recvfrom(4096)
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


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    filter_token = read_filter_token_from_env()
    server_address = (LISTEN_HOST, LISTEN_PORT)

    with ThreadingUDPServer(server_address, DNSProxyHandler) as server:
        server.filter_token = filter_token

        logging.info("Listening on %s:%s", *server_address)
        logging.info("Forwarding DNS queries to %s:%s", UPSTREAM_HOST, UPSTREAM_PORT)
        server.serve_forever()


if __name__ == "__main__":
    main()