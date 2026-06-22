"""Application-specific errors with safe user-facing messages."""

from __future__ import annotations


class AppError(Exception):
    """Base error carrying a safe message for CLI and web users."""

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class ConfigValidationError(AppError):
    """Configuration input is invalid or incomplete."""


class SourceFetchError(AppError):
    """A remote source could not be fetched."""


class SourceParseError(AppError):
    """A remote source response could not be parsed."""


class StorageError(AppError):
    """Local storage failed."""


class RunAlreadyInProgressError(AppError):
    """A vulnerability collection run is already active."""
