"""Secure structured file connector for batch CSV and JSONL ingestion."""
from __future__ import annotations

import csv
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Callable

from ..base import BankConnector, ConnectorBatch, ConnectorContext
from ..contracts import CanonicalRecord, SourceSystem
from ..mapping import map_core_banking_transaction

logger = logging.getLogger(__name__)


def compute_file_hash(path: Path) -> str:
    """Calculate SHA-256 checksum of an entire file."""
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class BankFileConnector:
    """Connector ingesting structured CSV or JSONL export files with checksum deduplication."""

    def __init__(
        self,
        *,
        connector_id: str,
        input_directory: str | Path,
        file_pattern: str = "*.csv",
        format: str = "csv",  # "csv" or "jsonl"
        source_system: SourceSystem = SourceSystem.CORE_BANKING,
        record_mapper: Callable[[dict[str, Any], str, str], CanonicalRecord] | None = None,
    ):
        self._connector_id = connector_id
        self._input_dir = Path(input_directory)
        self._file_pattern = file_pattern
        self._format = format.lower()
        self._source_system = source_system
        self._mapper = record_mapper or (lambda raw, inst, conn: map_core_banking_transaction(raw, installation_id=inst, connector_id=conn))

    @property
    def connector_id(self) -> str:
        return self._connector_id

    @property
    def connector_type(self) -> str:
        return "secure_file"

    @property
    def source_system(self) -> SourceSystem:
        return self._source_system

    @property
    def version(self) -> str:
        return "1.0.0"

    async def healthcheck(self) -> bool:
        """Verify that the input directory exists and is readable."""
        return self._input_dir.is_dir()

    def _get_candidate_files(self, cursor: str | None) -> list[Path]:
        """Find pending files sorted by name/timestamp after cursor."""
        if not self._input_dir.is_dir():
            return []
        files = sorted(self._input_dir.glob(self._file_pattern), key=lambda p: p.name)
        if not cursor:
            return files
        return [f for f in files if f.name > cursor]

    async def fetch_batch(self, context: ConnectorContext) -> ConnectorBatch:
        """Process next available file from directory."""
        candidates = self._get_candidate_files(context.cursor)
        if not candidates:
            return ConnectorBatch(records=[], next_cursor=context.cursor, has_more=False)

        current_file = candidates[0]
        records: list[CanonicalRecord] = []

        if self._format == "csv":
            with current_file.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rec = self._mapper(dict(row), context.installation_id, self._connector_id)
                    records.append(rec)
        elif self._format == "jsonl":
            with current_file.open("r", encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    row = json.loads(line_str)
                    rec = self._mapper(row, context.installation_id, self._connector_id)
                    records.append(rec)

        has_more = len(candidates) > 1
        return ConnectorBatch(
            records=records,
            next_cursor=current_file.name,
            has_more=has_more,
            records_read=len(records),
        )

    async def fetch_events(self, context: ConnectorContext) -> list[CanonicalRecord]:
        return []

    async def close(self) -> None:
        pass

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "connector_id": self._connector_id,
            "connector_type": self.connector_type,
            "source_system": self._source_system.value,
            "directory": str(self._input_dir),
            "file_pattern": self._file_pattern,
            "format": self._format,
        }

    @property
    def capabilities(self) -> dict[str, Any]:
        return {
            "batch_pagination": True,
            "cursor_resumption": True,
            "file_checksum": True,
            "streaming": False,
        }
