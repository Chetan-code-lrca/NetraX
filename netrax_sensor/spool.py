"""Bounded, crash-safe local outbox for NetraX telemetry events."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Iterable

from jsonschema import Draft202012Validator, FormatChecker


_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "telemetry-v1.schema.json"
)


class SpoolError(Exception):
    """Base error for local telemetry spool operations."""


class SpoolFullError(SpoolError):
    """Raised instead of silently dropping telemetry when capacity is full."""


class DuplicateEventConflict(SpoolError):
    """Raised when the same event ID is reused with different content."""


class SpoolCorruptionError(SpoolError):
    """Raised when a queued event is unreadable or no longer schema-valid."""


class SpoolCapacityError(SpoolError):
    """Raised for invalid or exceeded batch/event limits."""


def _load_validator() -> Draft202012Validator:
    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(schema, format_checker=FormatChecker())
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SpoolError("Telemetry v1 schema is missing or invalid.") from error


def _canonical_event_bytes(event: dict) -> bytes:
    return json.dumps(
        event,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _event_filename(event_id: str) -> str:
    # Hash the ID rather than using user-controlled text as a path component.
    return hashlib.sha256(event_id.encode("utf-8")).hexdigest() + ".json"


class DiskSpool:
    """Single-process, bounded, durable event spool.

    Each event is stored as one atomically replaced JSON file. The caller must
    acknowledge only after the receiver confirms durable acceptance. Re-reading
    a batch is safe and intentional: delivery is at-least-once, while the
    receiver deduplicates using authenticated sensor identity + event_id.

    This class is designed for one sensor process writing to one spool
    directory. It is not a multi-process shared queue or a distributed broker.
    """

    def __init__(
        self,
        directory: str | Path,
        *,
        max_bytes: int = 256 * 1024 * 1024,
        max_events: int = 100_000,
        max_event_bytes: int = 1_000_000,
        max_event_age_seconds: int = 7 * 24 * 60 * 60,
    ):
        for name, value in (
            ("max_bytes", max_bytes),
            ("max_events", max_events),
            ("max_event_bytes", max_event_bytes),
            ("max_event_age_seconds", max_event_age_seconds),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero.")
        if max_event_bytes > max_bytes:
            raise ValueError("max_event_bytes cannot exceed max_bytes.")

        self.directory = Path(directory)
        self.max_bytes = int(max_bytes)
        self.max_events = int(max_events)
        self.max_event_bytes = int(max_event_bytes)
        self.max_event_age_seconds = int(max_event_age_seconds)
        self._lock = threading.RLock()
        self._validator = _load_validator()

        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise SpoolError(f"Cannot create spool directory: {self.directory}") from error

        if not self.directory.is_dir() or self.directory.is_symlink():
            raise SpoolError("Spool path must be a real directory, not a symlink.")

        if os.name != "nt":
            try:
                os.chmod(self.directory, 0o700)
            except OSError as error:
                raise SpoolError("Cannot restrict spool directory permissions.") from error

        self._cleanup_orphan_temp_files()

    def _cleanup_orphan_temp_files(self) -> None:
        # The spool is single-process. Any matching temp file present at
        # startup was left by an interrupted write and was never committed.
        for path in self.directory.glob(".netrax-event-*.tmp"):
            try:
                if path.is_symlink() or not path.is_file():
                    raise SpoolCorruptionError(
                        f"Unexpected temporary spool entry: {path.name}"
                    )
                path.unlink()
            except OSError as error:
                raise SpoolError(
                    f"Cannot clean interrupted spool write: {path.name}"
                ) from error

    def _event_files(self) -> list[Path]:
        try:
            return sorted(
                self.directory.glob("*.json"),
                key=lambda path: (path.stat().st_mtime_ns, path.name),
            )
        except OSError as error:
            raise SpoolError("Cannot enumerate local spool files.") from error

    def _validate_event(self, event: dict) -> tuple[str, bytes]:
        if not isinstance(event, dict):
            raise SpoolError("Telemetry event must be a JSON object.")
        errors = list(self._validator.iter_errors(event))
        if errors:
            first = errors[0]
            location = ".".join(str(part) for part in first.absolute_path)
            raise SpoolError(
                f"Telemetry event failed schema validation at {location}: {first.message}"
            )

        event_id = event.get("event_id")
        if not isinstance(event_id, str):
            raise SpoolError("Telemetry event requires a string event_id.")
        payload = _canonical_event_bytes(event)
        if len(payload) > self.max_event_bytes:
            raise SpoolCapacityError(
                f"Event is {len(payload)} bytes; max_event_bytes is {self.max_event_bytes}."
            )
        return event_id, payload

    def purge_expired(self, *, now: float | None = None) -> int:
        """Delete events older than the configured local enqueue-time TTL."""
        current = time.time() if now is None else float(now)
        cutoff = current - self.max_event_age_seconds
        removed = 0
        with self._lock:
            for path in self._event_files():
                try:
                    if path.stat().st_mtime < cutoff:
                        path.unlink()
                        removed += 1
                except FileNotFoundError:
                    continue
                except OSError as error:
                    raise SpoolError(f"Cannot purge expired spool entry: {path.name}") from error
        return removed

    def _usage(self) -> tuple[int, int]:
        event_count = 0
        byte_count = 0
        for path in self._event_files():
            try:
                stat = path.stat()
            except FileNotFoundError:
                continue
            event_count += 1
            byte_count += stat.st_size
        return event_count, byte_count

    def append(self, event: dict) -> bool:
        """Persist one schema-valid event; return False for an exact duplicate."""
        event_id, payload = self._validate_event(event)
        name = _event_filename(event_id)
        destination = self.directory / name

        with self._lock:
            self.purge_expired()
            if destination.exists():
                try:
                    existing = destination.read_bytes()
                except OSError as error:
                    raise SpoolError(f"Cannot read existing spool entry: {name}") from error
                if existing == payload:
                    return False
                raise DuplicateEventConflict(
                    "event_id already exists in the spool with different content."
                )

            event_count, byte_count = self._usage()
            if event_count + 1 > self.max_events:
                raise SpoolFullError(
                    f"Spool event capacity reached ({self.max_events})."
                )
            if byte_count + len(payload) > self.max_bytes:
                raise SpoolFullError(
                    f"Spool byte capacity reached ({self.max_bytes})."
                )

            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    dir=self.directory,
                    prefix=".netrax-event-",
                    suffix=".tmp",
                    delete=False,
                ) as handle:
                    temp_path = Path(handle.name)
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_path, destination)
                temp_path = None
                self._fsync_directory()
                return True
            except OSError as error:
                raise SpoolError("Failed to persist telemetry event to the local spool.") from error
            finally:
                if temp_path is not None:
                    try:
                        temp_path.unlink(missing_ok=True)
                    except OSError:
                        pass

    def read_batch(
        self,
        *,
        max_events: int = 500,
        max_bytes: int = 5 * 1024 * 1024,
    ) -> list[dict]:
        """Return the oldest queued events without removing or marking them sent."""
        if max_events <= 0 or max_bytes <= 0:
            raise ValueError("Batch limits must be greater than zero.")
        self.purge_expired()

        batch: list[dict] = []
        total_bytes = 0
        with self._lock:
            for path in self._event_files():
                if path.is_symlink() or not path.is_file():
                    raise SpoolCorruptionError(
                        f"Spool entry is not a regular file: {path.name}"
                    )
                try:
                    payload = path.read_bytes()
                except FileNotFoundError:
                    continue
                except OSError as error:
                    raise SpoolError(f"Cannot read spool entry: {path.name}") from error

                if len(payload) > self.max_event_bytes:
                    raise SpoolCorruptionError(
                        f"Spool entry exceeds the configured event limit: {path.name}"
                    )
                if batch and total_bytes + len(payload) > max_bytes:
                    break
                if not batch and len(payload) > max_bytes:
                    raise SpoolCapacityError(
                        f"First queued event ({len(payload)} bytes) exceeds batch max_bytes ({max_bytes})."
                    )

                try:
                    event = json.loads(payload.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise SpoolCorruptionError(
                        f"Spool entry is not valid JSON: {path.name}"
                    ) from error

                errors = list(self._validator.iter_errors(event))
                if errors:
                    raise SpoolCorruptionError(
                        f"Spool entry no longer satisfies telemetry v1: {path.name}"
                    )
                if path.name != _event_filename(event["event_id"]):
                    raise SpoolCorruptionError(
                        f"Spool filename does not match event_id: {path.name}"
                    )

                batch.append(event)
                total_bytes += len(payload)
                if len(batch) >= max_events:
                    break

        return batch

    def acknowledge(self, event_ids: Iterable[str]) -> int:
        """Remove only events explicitly acknowledged by the receiver."""
        removed = 0
        with self._lock:
            for event_id in event_ids:
                if not isinstance(event_id, str) or not event_id:
                    continue
                path = self.directory / _event_filename(event_id)
                try:
                    path.unlink()
                    removed += 1
                except FileNotFoundError:
                    continue
                except OSError as error:
                    raise SpoolError("Cannot remove acknowledged spool event.") from error
            if removed:
                self._fsync_directory()
        return removed

    def stats(self) -> dict:
        with self._lock:
            event_count, byte_count = self._usage()
            files = self._event_files()
            oldest_age = None
            if files:
                oldest_age = max(0.0, time.time() - files[0].stat().st_mtime)
            return {
                "queued_events": event_count,
                "queued_bytes": byte_count,
                "max_events": self.max_events,
                "max_bytes": self.max_bytes,
                "event_capacity_ratio": event_count / self.max_events,
                "byte_capacity_ratio": byte_count / self.max_bytes,
                "oldest_event_age_seconds": oldest_age,
            }

    def _fsync_directory(self) -> None:
        # Directory fsync is supported on POSIX; failure is surfaced because
        # the spool is intended to be durable across process/host restarts.
        descriptor = None
        try:
            descriptor = os.open(self.directory, os.O_RDONLY)
            os.fsync(descriptor)
        except OSError as error:
            if os.name == "nt":
                return
            raise SpoolError("Cannot fsync the local spool directory.") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
