"""Bound tabular flow ingestion before inference allocates an unbounded frame."""
from __future__ import annotations

from pathlib import Path
from typing import Union

import pandas as pd

MAX_FLOW_ROWS = 100_000


class InputLimitError(ValueError):
    """Raised when a supported input exceeds a documented processing limit."""


class InvalidFlowCSVError(ValueError):
    """Raised when an uploaded CSV is empty or cannot be parsed safely."""


def read_bounded_flow_csv(
    path: Union[str, Path],
    *,
    max_rows: int = MAX_FLOW_ROWS,
) -> pd.DataFrame:
    """Read at most max_rows + 1 rows and reject inputs above the cap."""
    if isinstance(max_rows, bool) or not isinstance(max_rows, int) or max_rows < 1:
        raise ValueError("max_rows must be a positive integer.")

    try:
        frame = pd.read_csv(path, nrows=max_rows + 1)
    except (
        pd.errors.EmptyDataError,
        pd.errors.ParserError,
        UnicodeDecodeError,
    ) as error:
        raise InvalidFlowCSVError(
            "The uploaded CSV is empty or invalid. Check its encoding, "
            "delimiter, and header row."
        ) from error

    if len(frame.index) > max_rows:
        raise InputLimitError(
            f"Input contains more than {max_rows:,} flow rows. "
            "Split the capture or CSV into smaller files and retry."
        )
    return frame
