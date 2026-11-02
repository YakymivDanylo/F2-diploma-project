"""One error envelope for every error path: {"error": {"code", "message", "details"}}."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

_HTTP_CODES = {404: "not_found", 405: "method_not_allowed"}


class ApiError(Exception):
  def __init__(
    self, status_code: int, code: str, message: str, details: dict[str, Any] | None = None
  ) -> None:
    super().__init__(message)
    self.status_code = status_code
    self.code = code
    self.message = message
    self.details = details or {}


def error_body(code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
  return {"error": {"code": code, "message": message, "details": details or {}}}


def install_error_handlers(app: FastAPI) -> None:
  @app.exception_handler(ApiError)
  async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
      status_code=exc.status_code, content=error_body(exc.code, exc.message, exc.details)
    )

  @app.exception_handler(RequestValidationError)
  async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
    return JSONResponse(
      status_code=422,
      content=error_body("validation_error", "request validation failed", {"errors": errors}),
    )

  @app.exception_handler(StarletteHTTPException)
  async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = _HTTP_CODES.get(exc.status_code, "http_error")
    return JSONResponse(status_code=exc.status_code, content=error_body(code, str(exc.detail)))

  @app.exception_handler(Exception)
  async def _unhandled(_: Request, __: Exception) -> JSONResponse:
    # Never leak the exception text to the client.
    return JSONResponse(
      status_code=500, content=error_body("internal_error", "internal server error")
    )
