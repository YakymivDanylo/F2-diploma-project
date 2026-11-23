"""Reject oversized request bodies before they are parsed (memory/CPU guard)."""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from blockchain_core import canonicalize
from node.errors import error_body


class _TooLarge(BaseException):  # not Exception: framework body readers must not swallow it
  pass


DEFAULT_BODY_LIMIT = 16 * 1024  # any HTTP path without its own limit
PEER_REGISTER_BODY_LIMIT = 8 * 1024  # a signed registration is well under 4 KiB


class BodyLimitMiddleware:
  """413 for any HTTP request whose body exceeds the limit of its path (`limits`, else
  `default`), whatever the method: no route can be used to buffer an unbounded body.

  Checks Content-Length up front and counts streamed chunks, so a chunked upload without a
  length header is stopped as soon as it crosses the limit.
  """

  def __init__(
    self, app: ASGIApp, limits: dict[str, int], default: int = DEFAULT_BODY_LIMIT
  ) -> None:
    self.app = app
    self.limits = limits
    self.default = default

  async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] != "http":  # websockets carry their own frame limits
      await self.app(scope, receive, send)
      return
    limit = self.limits.get(scope.get("path", ""), self.default)
    declared = dict(scope["headers"]).get(b"content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
      await self._reject(send, limit)
      return
    seen = 0
    started = False

    async def limited_receive() -> Message:
      nonlocal seen
      message = await receive()
      if message["type"] == "http.request":
        seen += len(message.get("body", b""))
        if seen > limit:
          raise _TooLarge
      return message

    async def tracking_send(message: Message) -> None:
      nonlocal started
      started = started or message["type"] == "http.response.start"
      await send(message)

    try:
      await self.app(scope, limited_receive, tracking_send)
    except _TooLarge:
      if not started:
        await self._reject(send, limit)

  @staticmethod
  async def _reject(send: Send, limit: int) -> None:
    body = canonicalize(
      error_body("payload_too_large", "request body is too large", {"max_bytes": limit})
    )
    headers = [
      (b"content-type", b"application/json"),
      (b"content-length", str(len(body)).encode()),
    ]
    await send({"type": "http.response.start", "status": 413, "headers": headers})
    await send({"type": "http.response.body", "body": body})
