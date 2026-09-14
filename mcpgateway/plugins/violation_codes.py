# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/plugins/violation_codes.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Gateway-specific plugin violation code mappings.

These constants map plugin violation codes to HTTP status codes for proper
error responses in the gateway's exception handlers.  They are gateway-specific
and therefore not part of the cpex framework package.
"""

# Standard
from dataclasses import dataclass
import logging
import re
from types import MappingProxyType
from typing import Any, Mapping, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    # Third-Party
    from cpex.framework import PluginViolation

# First-Party
from mcpgateway.common.models import JSONRPCError
from mcpgateway.utils.orjson_response import ORJSONResponse

logger = logging.getLogger(__name__)

# RFC 9110 §5.6.2 'token' pattern for header field names:
#   token = 1*tchar
#   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*"
#           / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
#           / DIGIT / ALPHA
_RFC9110_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


@dataclass(frozen=True)
class PluginViolationCode:
    """Plugin violation codes as an immutable dataclass object.

    Provide Mapping for violation codes to their corresponding HTTP status codes for proper error responses.
    """

    code: int
    name: str
    message: str


PLUGIN_VIOLATION_CODE_MAPPING: Mapping[str, PluginViolationCode] = MappingProxyType(
    # MappingProxyType will make sure the resulting object is immutable and hence this will act as a constant.
    {
        # Rate Limiting
        "RATE_LIMIT": PluginViolationCode(429, "RATE_LIMIT", "Used when rate limit is exceeded (rate_limiter plugin)"),
        # Resource & URI Validation
        "INVALID_URI": PluginViolationCode(400, "INVALID_URI", "Used when URI cannot be parsed or has invalid format (resource_filter, cedar, opa)"),
        "PROTOCOL_BLOCKED": PluginViolationCode(403, "PROTOCOL_BLOCKED", "Used when protocol/scheme is not allowed (resource_filter)"),
        "DOMAIN_BLOCKED": PluginViolationCode(403, "DOMAIN_BLOCKED", "Used when domain is in blocklist (resource_filter)"),
        "CONTENT_TOO_LARGE": PluginViolationCode(413, "CONTENT_TOO_LARGE", "Used when resource content exceeds size limit (resource_filter)"),
        # Content Moderation & Safety
        "CONTENT_MODERATION": PluginViolationCode(422, "CONTENT_MODERATION", "Used when harmful content is detected (content_moderation plugin)"),
        "MODERATION_ERROR": PluginViolationCode(503, "MODERATION_ERROR", "Used when moderation service fails (content_moderation plugin)"),
        "PII_DETECTED": PluginViolationCode(422, "PII_DETECTED", "Used when PII is detected in content (pii_filter plugin)"),
        "SENSITIVE_CONTENT": PluginViolationCode(422, "SENSITIVE_CONTENT", "Used when sensitive information is detected"),
        # Authentication & Authorization
        "INVALID_TOKEN": PluginViolationCode(401, "INVALID_TOKEN", "Used for invalid/expired tokens (simple_token_auth example)"),  # nosec B105 - Not a password; INVALID_TOKEN is a HTTP Status Code
        "API_KEY_REVOKED": PluginViolationCode(401, "API_KEY_REVOKED", "Used when API key has been revoked (custom_auth_example)"),
        "AUTH_REQUIRED": PluginViolationCode(401, "AUTH_REQUIRED", "Used when authentication is missing"),
        # Generic Violation Codes
        "PROHIBITED_CONTENT": PluginViolationCode(422, "PROHIBITED_CONTENT", "Used when content violates policy rules"),
        "BLOCKED_CONTENT": PluginViolationCode(403, "BLOCKED_CONTENT", "Used when content is explicitly blocked by policy"),
        "BLOCKED": PluginViolationCode(403, "BLOCKED", "Generic blocking violation"),
        "EXECUTION_ERROR": PluginViolationCode(500, "EXECUTION_ERROR", "Used when plugin execution fails"),
        "PROCESSING_ERROR": PluginViolationCode(500, "PROCESSING_ERROR", "Used when processing encounters an error"),
    }
)

VALID_HTTP_STATUS_CODES: dict[int, str] = {  # RFC 9110
    # 4xx — Client Error
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Content Too Large",  # (was "Payload Too Large" before RFC 9110)
    414: "URI Too Long",
    415: "Unsupported Media Type",
    416: "Range Not Satisfiable",
    417: "Expectation Failed",
    418: "(Unused)",
    421: "Misdirected Request",
    422: "Unprocessable Content",  # (was "Unprocessable Entity")
    423: "Locked",
    424: "Failed Dependency",
    425: "Too Early",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",
    # 5xx — Server Error
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    506: "Variant Also Negotiates",
    507: "Insufficient Storage",
    508: "Loop Detected",
    510: "Not Extended",
    511: "Network Authentication Required",
}


def validate_http_headers(headers: dict[str, str]) -> Optional[dict[str, str]]:
    """Validate headers according to RFC 9110.

    Args:
        headers: dict of headers

    Returns:
        Optional[dict[str, str]]: dictionary of valid headers

    Rules enforced:
      - Header name must match RFC 9110 'token'.
      - No whitespace before colon (enforced by dictionary usage).
      - Header value must not contain CTL characters (0x00–0x1F, 0x7F),
        except SP (0x20) and HTAB (0x09) which are allowed.
    """
    validated: dict[str, str] = {}
    for key, value in headers.items():
        # Validate header name (RFC 9110 token)
        if not _RFC9110_TOKEN_RE.match(key):
            logger.warning(f"Invalid header name: {key}")
            continue
        # RFC 9110: Reject CTLs (0x00–0x1F, 0x7F). Allow SP (0x20) and HTAB (0x09).
        valid = True
        for ch in value:
            code = ord(ch)
            if (0 <= code <= 31 or code == 127) and code not in (9, 32):
                valid = False
                break
        if not valid:
            logger.warning(f"Header value contains invalid characters: {key}")
            continue
        validated[key] = value
    return validated if validated else None


def resolve_violation_http_status(violation: Optional["PluginViolation"]) -> int:
    """Resolve the HTTP status a plugin violation should be reported with.

    Precedence used by every surface that reports a violation:

    1. ``violation.http_status_code``, when it is a status the gateway recognises.
    2. The ``PLUGIN_VIOLATION_CODE_MAPPING`` entry for ``violation.code``.
    3. 200, so JSON-RPC clients keep reading the error out of the envelope.

    Args:
        violation: The violation reported by a plugin, or ``None`` when a plugin
            halted the pipeline without supplying details.

    Returns:
        int: The HTTP status code to send to the client.

    Examples:
        >>> from cpex.framework import PluginViolation
        >>> rate_limited = PluginViolation(reason="RATE_LIMIT", description="Slow down", code="RATE_LIMIT")
        >>> resolve_violation_http_status(rate_limited)
        429
        >>> explicit = PluginViolation(reason="x", description="y", code="RATE_LIMIT", http_status_code=403)
        >>> resolve_violation_http_status(explicit)
        403
        >>> unparsable = PluginViolation(reason="x", description="y", code="NOT_MAPPED", http_status_code=599)
        >>> resolve_violation_http_status(unparsable)
        200
        >>> resolve_violation_http_status(None)
        200
    """
    if not violation:
        return 200

    # Use HTTP status code from violation if present (e.g. 429 for rate limiting)
    http_status = violation.http_status_code if violation.http_status_code else None
    if http_status and not VALID_HTTP_STATUS_CODES.get(http_status):
        logger.warning(f"Invalid HTTP status code {http_status} from violation, defaulting to 200")
        http_status = None
    if not http_status:
        logger.debug("Using Plugin violation code mapping for lack of http_status_code")
        mapping: Optional[PluginViolationCode] = PLUGIN_VIOLATION_CODE_MAPPING.get(violation.code) if violation.code else None
        if not mapping:
            http_status = 200
        else:
            http_status = mapping.code
    return http_status


def build_violation_response(violation: Optional["PluginViolation"]) -> ORJSONResponse:
    """Build the gateway's HTTP response for a plugin violation.

    Shared by the app-level ``plugin_violation_exception_handler`` (violations that
    surface as exceptions from inside a handler) and the HTTP pre-request middleware
    (violations returned by a plugin that halts the pipeline).  Keeping one builder
    means a client sees the same envelope and status whichever path blocked it.

    Args:
        violation: The violation reported by a plugin, or ``None`` when a plugin
            halted the pipeline without supplying details.

    Returns:
        ORJSONResponse: JSON-RPC error envelope carrying the plugin's message, with
            the status code resolved by :func:`resolve_violation_http_status` and any
            RFC 9110-valid response headers the plugin asked for.

    Examples:
        >>> from cpex.framework import PluginViolation
        >>> violation = PluginViolation(
        ...     reason="RATE_LIMIT",
        ...     description="Rate limit exceeded",
        ...     code="RATE_LIMIT",
        ...     http_status_code=429,
        ...     http_headers={"Retry-After": "60"},
        ... )
        >>> response = build_violation_response(violation)
        >>> response.status_code
        429
        >>> response.headers["retry-after"]
        '60'
        >>> import json
        >>> json.loads(response.body.decode())["error"]["message"]
        'Plugin Violation: Rate limit exceeded'
    """
    message = violation.description if violation else "A plugin violation occurred."
    violation_details: dict[str, Any] = {}
    if violation:
        if violation.description:
            violation_details["description"] = violation.description
        if violation.details:
            violation_details["details"] = violation.details
        if violation.code:
            violation_details["plugin_error_code"] = violation.code
        if violation.plugin_name:
            violation_details["plugin_name"] = violation.plugin_name

    mcp_error_code = violation.mcp_error_code if violation and violation.mcp_error_code else -32602
    json_rpc_error = JSONRPCError(code=mcp_error_code, message="Plugin Violation: " + message, data=violation_details)

    response = ORJSONResponse(status_code=resolve_violation_http_status(violation), content={"error": json_rpc_error.model_dump()})

    # Collect HTTP headers from violation if present
    headers = violation.http_headers if violation and violation.http_headers else None
    if headers:
        validated_headers = validate_http_headers(headers)
        if validated_headers:
            response.headers.update(validated_headers)
    return response
