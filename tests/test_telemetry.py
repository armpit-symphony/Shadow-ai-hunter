"""
Unit tests for backend/workers/telemetry_worker.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend", "workers"))

import pytest

from telemetry_worker import (
    parse_dns_log,
    parse_proxy_log,
    extract_domain,
    extract_timestamp,
    normalize_event,
    process_log_file,
)


class TestExtractDomain:
    def test_https_url(self):
        assert extract_domain("https://api.openai.com/v1/chat") == "api.openai.com"

    def test_http_url(self):
        assert extract_domain("http://claude.ai/chat") == "claude.ai"

    def test_url_with_port(self):
        assert extract_domain("http://api.openai.com:443/path") == "api.openai.com"

    def test_bare_domain(self):
        assert extract_domain("api.openai.com") == "api.openai.com"

    def test_empty_string(self):
        assert extract_domain("") == ""


class TestParseDnsLog:
    def test_dnsmasq_query_format(self):
        line = "Feb 26 10:00:00 host dnsmasq[123]: query[A] api.openai.com from 192.168.1.100"
        result = parse_dns_log(line)
        assert result is not None
        assert result["domain"] == "api.openai.com"
        assert result["source_ip"] == "192.168.1.100"
        assert result["query_type"] == "A"
        assert result["type"] == "dns_query"

    def test_dnsmasq_reply_format(self):
        line = "Feb 26 10:00:01 host dnsmasq[123]: reply api.openai.com is 104.18.7.192"
        result = parse_dns_log(line)
        assert result is not None
        assert result["domain"] == "api.openai.com"
        assert result["resolved_ip"] == "104.18.7.192"
        assert result["type"] == "dns_reply"

    def test_aaaa_query(self):
        line = "Feb 26 10:00:00 host dnsmasq[1]: query[AAAA] claude.ai from 10.0.0.5"
        result = parse_dns_log(line)
        assert result is not None
        assert result["query_type"] == "AAAA"
        assert result["domain"] == "claude.ai"

    def test_unrecognised_line_returns_none(self):
        result = parse_dns_log("random log line with no dns content")
        assert result is None

    def test_empty_line_returns_none(self):
        result = parse_dns_log("")
        assert result is None


class TestParseProxyLog:
    def test_squid_style_log(self):
        line = (
            '192.168.1.5 - - [26/Feb/2026:10:00:00 +0000] '
            '"GET https://api.openai.com/v1/chat HTTP/1.1" '
            '200 5120 "-" "openai-python/1.0"'
        )
        result = parse_proxy_log(line)
        assert result is not None
        assert result["source_ip"] == "192.168.1.5"
        assert result["dest_domain"] == "api.openai.com"
        assert result["method"] == "GET"
        assert result["status_code"] == 200
        assert result["bytes_out"] == 5120

    def test_post_request(self):
        line = (
            '10.0.1.50 - - [27/Feb/2026:09:30:00 +0000] '
            '"POST https://api.anthropic.com/v1/messages HTTP/1.1" '
            '200 2048 "-" "anthropic-sdk/0.1"'
        )
        result = parse_proxy_log(line)
        assert result is not None
        assert result["method"] == "POST"
        assert result["dest_domain"] == "api.anthropic.com"

    def test_unrecognised_line_returns_none(self):
        result = parse_proxy_log("not a valid proxy log line")
        assert result is None


class TestNormalizeEvent:
    def test_dns_event_normalised(self):
        raw = {
            "type": "dns_query",
            "domain": "api.openai.com",
            "source_ip": "192.168.1.5",
            "timestamp": "2026-02-27T10:00:00",
        }
        norm = normalize_event(raw)
        assert norm["dest_domain"] == "api.openai.com"
        assert norm["source"] == "192.168.1.5"

    def test_proxy_event_normalised(self):
        raw = {
            "type": "http_request",
            "source_ip": "10.0.0.1",
            "dest_domain": "claude.ai",
            "bytes_out": 1234,
            "user_agent": "anthropic-sdk",
        }
        norm = normalize_event(raw)
        assert norm["dest_domain"] == "claude.ai"
        assert norm["bytes_out"] == 1234
        assert norm["user_agent"] == "anthropic-sdk"

    def test_missing_fields_default_to_empty(self):
        norm = normalize_event({})
        assert norm["dest_domain"] == ""
        assert norm["bytes_out"] == 0


class TestProcessLogFile:
    def test_nonexistent_file_returns_empty(self, tmp_path):
        result = process_log_file(str(tmp_path / "nonexistent.log"), "dns")
        assert result == []

    def test_dns_log_file(self, tmp_path):
        log_file = tmp_path / "dns.log"
        log_file.write_text(
            "Feb 26 10:00:00 host dnsmasq[1]: query[A] api.openai.com from 192.168.1.5\n"
            "Feb 26 10:00:01 host dnsmasq[1]: query[A] example.com from 192.168.1.5\n"
        )
        events = process_log_file(str(log_file), "dns")
        ai_events = [e for e in events if e.get("dest_domain") == "api.openai.com"]
        assert len(ai_events) == 1

    def test_proxy_log_file(self, tmp_path):
        log_file = tmp_path / "proxy.log"
        log_file.write_text(
            '10.0.1.5 - - [26/Feb/2026:10:00:00 +0000] "GET https://claude.ai/ HTTP/1.1" 200 512 "-" "-"\n'
        )
        events = process_log_file(str(log_file), "proxy")
        assert len(events) == 1
        assert events[0]["dest_domain"] == "claude.ai"
