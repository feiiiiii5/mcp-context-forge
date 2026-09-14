# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/plugins/test_violation_codes.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Tests for the shared plugin-violation -> HTTP response helpers.

These helpers are the single place where a ``PluginViolation`` is turned into the
status code, JSON-RPC error envelope and response headers the gateway sends back.
"""

# Third-Party
from cpex.framework import PluginViolation
import orjson
import pytest

# First-Party
from mcpgateway.plugins.violation_codes import build_violation_response, resolve_violation_http_status


def _violation(**overrides):
    """Build a violation, overriding only the fields a test cares about."""
    kwargs = {
        "reason": "RATE_LIMIT",
        "description": "Rate limit exceeded",
        "code": "RATE_LIMIT",
    }
    kwargs.update(overrides)
    return PluginViolation(**kwargs)


def test_explicit_status_code_wins_over_code_mapping():
    assert resolve_violation_http_status(_violation(code="RATE_LIMIT", http_status_code=403)) == 403


def test_unparsable_status_code_falls_back_to_code_mapping():
    """A status the gateway does not recognise must not be echoed to the client."""
    assert resolve_violation_http_status(_violation(code="DOMAIN_BLOCKED", http_status_code=599)) == 403


def test_unmapped_code_without_status_defaults_to_200_for_jsonrpc_compliance():
    assert resolve_violation_http_status(_violation(code="my_custom_rate_limit")) == 200


def test_missing_violation_defaults_to_200():
    assert resolve_violation_http_status(None) == 200


def test_response_carries_the_plugin_violation_envelope():
    response = build_violation_response(
        _violation(code="PROHIBITED_CONTENT", http_status_code=429, http_headers={"Retry-After": "60"}),
    )

    assert response.status_code == 429
    body = orjson.loads(response.body)
    assert body["error"]["code"] == -32602
    assert body["error"]["message"] == "Plugin Violation: Rate limit exceeded"
    assert body["error"]["data"]["plugin_error_code"] == "PROHIBITED_CONTENT"
    assert body["error"]["data"]["description"] == "Rate limit exceeded"
    assert response.headers["retry-after"] == "60"


def test_response_honours_mcp_error_code():
    response = build_violation_response(_violation(mcp_error_code=-32001))

    assert orjson.loads(response.body)["error"]["code"] == -32001


@pytest.mark.parametrize(
    "bad_name",
    ["X Bad", "X-Bad\r\n", "X:Bad", "Bad@Name"],
)
def test_invalid_header_names_are_dropped(bad_name):
    response = build_violation_response(_violation(http_headers={bad_name: "value", "Retry-After": "60"}))

    assert bad_name not in response.headers
    assert response.headers["retry-after"] == "60"


def test_crlf_in_header_value_is_dropped_not_forwarded():
    """Response splitting guard: a CTL in a plugin-supplied value kills that header only."""
    response = build_violation_response(
        _violation(http_headers={"X-Bad": "value\r\nX-Injected: yes", "Retry-After": "60"}),
    )

    assert "x-bad" not in response.headers
    assert "x-injected" not in response.headers
    assert response.headers["retry-after"] == "60"


def test_no_headers_added_when_violation_carries_none():
    response = build_violation_response(_violation())

    assert "retry-after" not in response.headers
