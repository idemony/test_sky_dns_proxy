import argparse
import logging
import sys
from pathlib import Path

import pytest
from dnslib import DNSRecord, EDNS0, EDNSOption, QTYPE

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dns_proxy import (
    CATEGORIES_OPTION_CODE,
    FILTER_TOKEN_OPTION_CODE,
    add_filter_token_option,
    iter_response_categories,
    parse_filter_token,
)


def _get_opt_options(packet: bytes) -> list[EDNSOption]:
    record = DNSRecord.parse(packet)

    options = []
    for additional_record in record.ar:
        if additional_record.rtype == QTYPE.OPT:
            options.extend(additional_record.rdata)

    return options


def _get_opt_record(packet: bytes):
    record = DNSRecord.parse(packet)

    for additional_record in record.ar:
        if additional_record.rtype == QTYPE.OPT:
            return additional_record

    raise AssertionError("OPT record not found")


@pytest.mark.parametrize(
    ("token_value", "expected"),
    [
        ("123456", b"\x00\x01\xe2\x40"),
        ("0x01020304", b"\x01\x02\x03\x04"),
        ("https://abcdef12.doh.skydns.ru", bytes.fromhex("abcdef12")),
        ("https://abcdef12.doh.skydns.ru/", bytes.fromhex("abcdef12")),
    ],
)
def test_parse_filter_token_supported_formats(token_value, expected):
    assert parse_filter_token(token_value) == expected


@pytest.mark.parametrize("token_value", ["-1", "0x100000000", "not-a-token"])
def test_parse_filter_token_rejects_invalid_values(token_value):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_filter_token(token_value)


def test_add_filter_token_option_adds_custom_edns_option():
    query = DNSRecord.question("mail.yandex.ru", "A")
    token = b"\x01\x02\x03\x04"

    modified_packet = add_filter_token_option(query.pack(), token)

    options = _get_opt_options(modified_packet)
    matching_options = [
        option
        for option in options
        if option.code == FILTER_TOKEN_OPTION_CODE and bytes(option.data) == token
    ]

    assert len(matching_options) == 1


def test_add_filter_token_option_preserves_existing_edns_options_and_parameters():
    query = DNSRecord.question("mail.yandex.ru", "A")
    existing_option = EDNSOption(12345, b"existing")
    opt_record = EDNS0(udp_len=4096, opts=[existing_option])
    opt_record.ttl = 0x8000
    query.add_ar(opt_record)

    token = b"\x01\x02\x03\x04"
    modified_packet = add_filter_token_option(query.pack(), token)

    opt_record_after = _get_opt_record(modified_packet)
    options_after = _get_opt_options(modified_packet)

    assert opt_record_after.rclass == 4096
    assert opt_record_after.ttl == 0x8000
    assert any(option.code == 12345 and bytes(option.data) == b"existing" for option in options_after)
    assert any(
        option.code == FILTER_TOKEN_OPTION_CODE and bytes(option.data) == token
        for option in options_after
    )


def test_add_filter_token_option_replaces_existing_filter_token_option():
    query = DNSRecord.question("mail.yandex.ru", "A")
    query.add_ar(
        EDNS0(
            opts=[
                EDNSOption(FILTER_TOKEN_OPTION_CODE, b"\x00\x00\x00\x00"),
            ],
        )
    )

    modified_packet = add_filter_token_option(query.pack(), b"\x01\x02\x03\x04")

    filter_token_options = [
        option
        for option in _get_opt_options(modified_packet)
        if option.code == FILTER_TOKEN_OPTION_CODE
    ]

    assert len(filter_token_options) == 1
    assert bytes(filter_token_options[0].data) == b"\x01\x02\x03\x04"


def test_iter_response_categories_yields_valid_8_byte_category_payload():
    response = DNSRecord.question("mail.yandex.ru", "A").reply()
    response.add_ar(
        EDNS0(
            opts=[
                EDNSOption(CATEGORIES_OPTION_CODE, b"\x38\x00\x00\x00\x00\x00\x00\x00"),
            ],
        )
    )

    assert list(iter_response_categories(response.pack())) == [[56, 0, 0, 0, 0, 0, 0, 0]]


def test_iter_response_categories_ignores_invalid_payload_length(caplog):
    response = DNSRecord.question("mail.yandex.ru", "A").reply()
    response.add_ar(
        EDNS0(
            opts=[
                EDNSOption(CATEGORIES_OPTION_CODE, b"\x38\x00"),
            ],
        )
    )

    with caplog.at_level(logging.WARNING):
        categories = list(iter_response_categories(response.pack()))

    assert categories == []
    assert "Invalid categories length" in caplog.text
