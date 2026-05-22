#!/usr/bin/env python3
"""
Basic UDP DNS proxy.

Listens on 127.0.0.1:5353, forwards DNS queries to SkyDNS and returns
upstream responses to clients unchanged.
"""

from __future__ import annotations

import logging
import socket
import socketserver

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5353

UPSTREAM_HOST = "193.58.251.251"
UPSTREAM_PORT = 53

UPSTREAM_TIMEOUT = 3.0


class DNSProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client_packet, client_socket = self.request
        client_ip, client_port = self.client_address

        logging.info("Received DNS query from %s:%s", client_ip, client_port)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_socket:
                upstream_socket.settimeout(UPSTREAM_TIMEOUT)
                upstream_socket.sendto(client_packet, (UPSTREAM_HOST, UPSTREAM_PORT))
                response_packet, _ = upstream_socket.recvfrom(4096)
        except socket.timeout:
            logging.warning("Upstream DNS timeout for client %s:%s", client_ip, client_port)
            return
        except OSError:
            logging.exception("Failed to query upstream DNS server")
            return

        client_socket.sendto(response_packet, self.client_address)


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    server_address = (LISTEN_HOST, LISTEN_PORT)

    with ThreadingUDPServer(server_address, DNSProxyHandler) as server:
        logging.info("Listening on %s:%s", *server_address)
        logging.info("Forwarding DNS queries to %s:%s", UPSTREAM_HOST, UPSTREAM_PORT)
        server.serve_forever()


if __name__ == "__main__":
    main()