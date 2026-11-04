"""Bounded, durable replay progress checkpoints for resumable PCAP enqueue."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path


class CheckpointError(Exception):
    """Raised when replay progress cannot be safely loaded or persisted."""


class ReplayCheckpointStore:
    """Persist the next flow index for each capture/config identity.

    Checkpoints are separate from queued events. They let a replay resume after
    spool backpressure even if already-enqueued events have been acknowledged
    and removed from the outbox.
    """

    def __init__(
        self,
        spool_directory: str | Path,
        *,
        ttl_seconds: int = 7 * 24 * 60 * 60,
        max_records: int = 10_000,
    ):
        if ttl_seconds <= 0 or max_records <= 0:
            raise ValueError("Checkpoint TTL and max_records must be positive.")
        self.directory = Path(spool_directory) / ".checkpoints"
        self.ttl_seconds = int(ttl_seconds)
        self.max_records = int(max_records)
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.directory.is_symlink() or not self.directory.is_dir():
                raise CheckpointError("Checkpoint path must be a real directory.")
            if os.name != "nt":
                os.chmod(self.directory, 0o700)
        except OSError as error:
            raise CheckpointError("Cannot create private replay checkpoint directory.") from error
        self._cleanup_orphan_temp_files()
        self.purge_expired()

    def _cleanup_orphan_temp_files(self) -> None:
        # A temporary file present during process startup was left by an
        # interrupted atomic save and was never committed as a checkpoint.
        for path in self.directory.glob(".netrax-checkpoint-*.tmp"):
            try:
                if path.is_dir() and not path.is_symlink():
                    raise CheckpointError(
                        f"Unexpected checkpoint temporary directory: {path.name}"
                    )
                path.unlink(missing_ok=True)
            except OSError as error:
                raise CheckpointError(
                    f"Cannot clean interrupted checkpoint write: {path.name}"
                ) from error

    @staticmethod
    def _identity_key(identity: dict) -> str:
        canonical = json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _path(self, identity: dict) -> Path:
        return self.directory / (self._identity_key(identity) + ".json")

    def purge_expired(self, *, now: float | None = None) -> int:
        current = time.time() if now is None else float(now)
        cutoff = current - self.ttl_seconds
        removed = 0
        for path in self.directory.glob("*.json"):
            try:
                if path.is_symlink() or not path.is_file():
                    raise CheckpointError(
                        f"Unexpected checkpoint entry: {path.name}"
                    )
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            except FileNotFoundError:
                continue
            except OSError as error:
                raise CheckpointError(
                    f"Cannot purge expired replay checkpoint: {path.name}"
                ) from error
        return removed

    def load(self, identity: dict, *, expected_total_flows: int) -> int:
        path = self._path(identity)
        if path.is_symlink():
            raise CheckpointError("Replay checkpoint path must not be a symlink.")
        if not path.exists():
            return 0
        if not path.is_file():
            raise CheckpointError("Replay checkpoint path is not a regular file.")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise CheckpointError(
                f"Replay checkpoint is unreadable: {path.name}"
            ) from error

        if not isinstance(payload, dict):
            raise CheckpointError("Replay checkpoint payload must be a JSON object.")
        if payload.get("identity") != identity:
            raise CheckpointError("Replay checkpoint identity does not match its key.")
        total_flows = payload.get("total_flows")
        if isinstance(total_flows, bool) or not isinstance(total_flows, int) or total_flows < 0:
            raise CheckpointError("Replay checkpoint total_flows is invalid.")
        if total_flows != expected_total_flows:
            raise CheckpointError(
                "Replay flow count changed for an existing capture/config checkpoint. "
                "Bump sensor_version or config_version before replaying changed extraction logic."
            )

        next_index = payload.get("next_flow_index")
        if isinstance(next_index, bool) or not isinstance(next_index, int) or not 0 <= next_index <= expected_total_flows:
            raise CheckpointError("Replay checkpoint next_flow_index is invalid.")
        return next_index

    def save(
        self,
        identity: dict,
        *,
        next_flow_index: int,
        total_flows: int,
    ) -> None:
        if (
            isinstance(next_flow_index, bool)
            or not isinstance(next_flow_index, int)
            or isinstance(total_flows, bool)
            or not isinstance(total_flows, int)
            or total_flows < 0
            or not 0 <= next_flow_index <= total_flows
        ):
            raise ValueError("next_flow_index must be an integer within the capture flow count.")

        destination = self._path(identity)
        if not destination.exists():
            current_records = sum(1 for _ in self.directory.glob("*.json"))
            if current_records >= self.max_records:
                raise CheckpointError(
                    f"Replay checkpoint capacity reached ({self.max_records})."
                )

        payload = {
            "identity": identity,
            "next_flow_index": next_flow_index,
            "total_flows": total_flows,
            "updated_at": time.time(),
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self.directory,
                prefix=".netrax-checkpoint-",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temp_path = Path(handle.name)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, destination)
            temp_path = None

            descriptor = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as error:
            raise CheckpointError("Failed to persist replay progress checkpoint.") from error
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
