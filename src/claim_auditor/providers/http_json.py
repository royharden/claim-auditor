"""Dormant bounded HTTPS source. Nothing connects, reads keys or runs at import."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
import math
import json
import multiprocessing
import re
import ssl
import time
from typing import Mapping, Protocol
from urllib.parse import urlsplit

from ..contracts import AuditError, LiveAuthorization, canonical_json, sha256


def validate_endpoint(endpoint: str) -> tuple[str, int, str]:
    parsed = urlsplit(endpoint)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path not in {"/v1/chat/completions", "/v1/messages"}
            or any(ord(char) <= 32 or ord(char) >= 127 for char in endpoint)):
        raise AuditError("invalid_provider_endpoint", "Owner must supply an exact HTTPS provider route without credentials/query/fragment.")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise AuditError("invalid_provider_endpoint", "Invalid endpoint port.") from exc
    return parsed.hostname, port, parsed.path


@dataclass(frozen=True)
class JSONReply:
    endpoint: str
    status_code: int
    body: bytes
    elapsed_seconds: float | None
    physical_attempts: int
    settled_cost_usd: float | None
    cost_receipt: str | None


class BoundedJSONTransport(Protocol):
    execution_kind: str
    authorization_id: str
    hidden_retries: int
    follows_redirects: bool

    def post_json(self, *, endpoint: str, body: bytes, headers: Mapping[str, str],
                  timeout_seconds: float, max_response_bytes: int,
                  max_attempts: int, follow_redirects: bool) -> JSONReply: ...


class HTTPJSONTransport:
    """One HTTPS POST; explicit credentials supplied by a later owner caller.

    Constructor performs no I/O. No environment/key lookup, SDK, proxy config,
    redirect, retry, cookie jar or target-derived address exists. TLS verification
    uses the system trust store at future call time; never disable it for a demo.
    """

    execution_kind = "live"
    hidden_retries = 0
    follows_redirects = False

    def __init__(self, *, authorization: LiveAuthorization, allowed_endpoints: tuple[str, ...],
                 credential_headers: Mapping[str, str], owner_activation: bool = False) -> None:
        if not owner_activation or not authorization.enabled or not allowed_endpoints:
            raise AuditError("live_not_authorized", "Explicit owner endpoint and authorization binding required.")
        for endpoint in allowed_endpoints:
            validate_endpoint(endpoint)
        if not credential_headers or any(key.lower() not in {"authorization", "x-api-key"}
                                         for key in credential_headers):
            raise AuditError("invalid_credential_binding", "Supply only owner credential headers; no environment lookup is performed.")
        if len({key.lower() for key in credential_headers}) != len(credential_headers):
            raise AuditError("invalid_credential_binding", "Duplicate credential header.")
        for key, value in credential_headers.items():
            if not value or len(value) > 8192 or any(char in value for char in "\r\n\x00"):
                raise AuditError("invalid_credential_binding", "Malformed owner credential header.")
        self._authorization = LiveAuthorization.model_validate_json(canonical_json(authorization))
        self.authorization_id = authorization.authorization_id
        self._endpoints = frozenset(allowed_endpoints)
        self._credentials = dict(credential_headers)

    def _check_authorization(self, endpoint: str, body: bytes, cap: int) -> None:
        authorization = self._authorization
        try:
            expires = datetime.fromisoformat(authorization.expires_at.replace("Z", "+00:00"))
            if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
                raise ValueError("expired")
        except ValueError as exc:
            raise AuditError("live_not_authorized", "Transport authorization is expired or invalid.") from exc
        if (not authorization.enabled or authorization.endpoint != endpoint
                or authorization.payload_digest != sha256(body)
                or len(body) > authorization.max_request_bytes or cap > authorization.max_response_bytes):
            raise AuditError("live_not_authorized", "Transport grant does not bind the exact endpoint/payload/limits.")

    def post_json(self, *, endpoint: str, body: bytes, headers: Mapping[str, str],
                  timeout_seconds: float, max_response_bytes: int,
                  max_attempts: int = 1, follow_redirects: bool = False) -> JSONReply:
        """Wall-bound a trusted child, including blocking DNS/TLS work.

        Only this call's worker is terminated. No broad process discovery or
        cleanup is used. Credentials travel through multiprocessing bootstrap,
        never command-line text, target files or environment variables.
        """
        if (endpoint not in self._endpoints or max_attempts != 1 or follow_redirects
                or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30
                or type(max_response_bytes) is not int or not 0 < max_response_bytes <= 2 * 1024 * 1024
                or not isinstance(body, bytes) or len(body) > 1024 * 1024):
            raise AuditError("invalid_transport_limits", "Explicit single-attempt endpoint and bounded limits required.")
        self._check_authorization(endpoint, body, max_response_bytes)
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        worker = context.Process(target=_http_worker,
                                 args=(send, self._authorization, tuple(self._endpoints),
                                       self._credentials, endpoint, body, dict(headers),
                                       timeout_seconds, max_response_bytes))
        started = time.monotonic()
        try:
            worker.start()
            send.close()
            remaining = timeout_seconds - (time.monotonic() - started)
            if remaining <= 0 or not receive.poll(remaining):
                raise AuditError("provider_deadline", "Provider worker exceeded total deadline; settlement unknown.", 3)
            envelope = receive.recv_bytes(maxlength=max_response_bytes + 4096)
            if time.monotonic() - started > timeout_seconds:
                raise AuditError("provider_deadline", "Late provider response refused.", 3)
            metadata, separator, raw = envelope.partition(b"\n")
            if not separator or len(metadata) > 4096:
                raise AuditError("invalid_transport_reply", "Malformed trusted worker envelope.")
            value = json.loads(metadata)
            if value.get("error") is not None:
                raise AuditError(value["error"], "Single bounded HTTPS attempt failed; settlement unknown.", 3)
            if type(value.get("status")) is not int or len(raw) > max_response_bytes:
                raise AuditError("invalid_transport_reply", "Malformed trusted worker response.")
            return JSONReply(endpoint, value["status"], raw, time.monotonic() - started, 1, None, None)
        except (EOFError, OSError) as exc:
            raise AuditError("provider_transport_failure", "Bounded worker did not return a valid response.", 3) from exc
        finally:
            receive.close()
            send.close()
            if worker.pid is not None:
                if worker.is_alive():
                    worker.terminate()
                worker.join(timeout=1)
                if worker.is_alive():
                    worker.kill()
                    worker.join(timeout=1)
                if worker.is_alive():
                    raise AuditError("provider_worker_cleanup_failed", "Owned worker termination remains unconfirmed; settlement unknown.", 3)
                worker.close()

    def _post_json_once(self, *, endpoint: str, body: bytes, headers: Mapping[str, str],
                        timeout_seconds: float, max_response_bytes: int,
                        max_attempts: int = 1, follow_redirects: bool = False) -> JSONReply:
        if endpoint not in self._endpoints or max_attempts != 1 or follow_redirects:
            raise AuditError("transport_scope_violation", "Exactly one POST to an owner-allowed endpoint is permitted.")
        self._check_authorization(endpoint, body, max_response_bytes)
        if (not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30
                or type(max_response_bytes) is not int or not 0 < max_response_bytes <= 2 * 1024 * 1024
                or not isinstance(body, bytes) or len(body) > 1024 * 1024):
            raise AuditError("invalid_transport_limits", "Request/response bytes and total deadline must be bounded.")
        host, port, route = validate_endpoint(endpoint)
        outgoing = {"Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity"}
        for key, value in headers.items():
            if (key.lower() not in {"anthropic-version"} or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value)):
                raise AuditError("invalid_provider_header", "Only a pinned Anthropic version may supplement trusted headers.")
            outgoing[key] = value
        outgoing.update(self._credentials)
        started = time.monotonic()
        deadline = started + timeout_seconds
        connection = http.client.HTTPSConnection(host, port, timeout=timeout_seconds,
                                                 context=ssl.create_default_context())

        def remaining() -> float:
            value = deadline - time.monotonic()
            if value <= 0:
                raise TimeoutError("provider total deadline exceeded")
            return value

        try:
            connection.connect()
            if connection.sock is None:
                raise OSError("provider connection unavailable")
            connection.sock.settimeout(remaining())
            connection.request("POST", route, body=body, headers=outgoing)
            connection.sock.settimeout(remaining())
            response = connection.getresponse()
            encoding = response.getheader("Content-Encoding", "identity").lower()
            if encoding not in {"", "identity"}:
                raise AuditError("encoded_provider_response", "Compressed responses are refused; no unbounded decompression.")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > max_response_bytes):
                raise AuditError("provider_response_too_large", "Declared response exceeds cap.")
            data = bytearray()
            while True:
                # read1 returns after an underlying read, so a slow trickle cannot
                # reset a whole-response deadline indefinitely.
                if connection.sock is not None:
                    connection.sock.settimeout(remaining())
                else:
                    remaining()
                chunk = response.read1(min(65536, max_response_bytes + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > max_response_bytes:
                    raise AuditError("provider_response_too_large", "Streaming response exceeded cap.")
            remaining()
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise AuditError("invalid_provider_content_type", "Only bounded JSON responses are admitted.")
            # No monetary usage is invented from tokens or a current price table.
            return JSONReply(endpoint, response.status, bytes(data), time.monotonic() - started,
                             1, None, None)
        except (OSError, http.client.HTTPException) as exc:
            # Do not expose server text, credential headers or endpoint secrets.
            raise AuditError("provider_transport_failure", "Single bounded HTTPS attempt failed; liability remains unknown.", 3) from exc
        finally:
            connection.close()


def _http_worker(send: object, authorization: LiveAuthorization, allowed_endpoints: tuple[str, ...],
                 credentials: dict[str, str], endpoint: str, body: bytes,
                 headers: dict[str, str], seconds: float, cap: int) -> None:
    """Trusted spawn entrypoint; not invoked during source construction."""
    try:
        transport = HTTPJSONTransport(authorization=authorization, owner_activation=True,
                                      allowed_endpoints=allowed_endpoints,
                                      credential_headers=credentials)
        reply = transport._post_json_once(endpoint=endpoint, body=body, headers=headers,
                                          timeout_seconds=seconds, max_response_bytes=cap)
        send.send_bytes(canonical_json({"error": None, "status": reply.status_code}) + b"\n" + reply.body)
    except Exception as exc:
        reason = exc.reason if isinstance(exc, AuditError) else "provider_transport_failure"
        send.send_bytes(canonical_json({"error": reason}) + b"\n")
    finally:
        send.close()


class StaticJSONTransport:
    """Future regression fixture source; never labels synthetic usage as live."""

    execution_kind = "fixture"
    hidden_retries = 0
    follows_redirects = False

    def __init__(self, *, authorization_id: str, replies: list[JSONReply]) -> None:
        self.authorization_id = authorization_id
        self._replies = tuple(replies)
        self._position = 0

    def post_json(self, *, endpoint: str, body: bytes, headers: Mapping[str, str],
                  timeout_seconds: float, max_response_bytes: int,
                  max_attempts: int, follow_redirects: bool) -> JSONReply:
        if max_attempts != 1 or follow_redirects or self._position >= len(self._replies):
            raise AuditError("fixture_missing", "No hidden attempts or last-item fallback.")
        reply = self._replies[self._position]
        self._position += 1
        return reply
