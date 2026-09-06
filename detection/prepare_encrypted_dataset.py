import ast
import math
from typing import Any


def _is_missing(value: Any) -> bool:
    """Return True for None / NaN / empty string."""
    if value is None:
        return True

    if isinstance(value, float):
        return math.isnan(value)

    if isinstance(value, str):
        return not value.strip()

    return False


def safe_len(value: Any) -> int:
    """
    Safely count elements in list-like metadata.

    Handles:
      - Python lists/tuples
      - string representations of lists
      - None/NaN
    """
    if _is_missing(value):
        return 0

    if isinstance(value, (list, tuple, set)):
        return len(value)

    if isinstance(value, str):
        text = value.strip()

        if not text:
            return 0

        try:
            parsed = ast.literal_eval(text)

            if isinstance(parsed, (list, tuple, set)):
                return len(parsed)

        except (ValueError, SyntaxError):
            pass

        # Some datasets may contain comma-separated metadata.
        if "," in text:
            return len(
                [
                    item
                    for item in text.split(",")
                    if item.strip()
                ]
            )

    return 0


def safe_present(value: Any) -> int:
    """Return 1 when the metadata field is present."""
    return 0 if _is_missing(value) else 1


def safe_float(value: Any) -> float:
    """Convert a value to float, returning 0 on failure."""
    try:
        if _is_missing(value):
            return 0.0

        return float(value)

    except (TypeError, ValueError):
        return 0.0


def extract_encrypted_features(row) -> dict[str, float]:
    """
    Extract strictly one-way observable encrypted-traffic features.

    Allowed:
      - source-side byte/packet volume
      - flow duration
      - source/destination ports
      - TLS client-observable metadata
      - SNI presence
      - JA3 / JA4 presence
      - packet/byte rates

    Deliberately excluded:
      - reverse bytes (br)
      - reverse packets (pr)
      - server-side JA3S / JA4S
      - decrypted payload
      - application content
      - server response semantics
    """

    bytes_sent = safe_float(row.get("bs"))
    packets_sent = safe_float(row.get("ps"))
    duration = safe_float(row.get("td"))

    if duration > 0:
        bytes_per_second = bytes_sent / duration
        packets_per_second = packets_sent / duration
    else:
        bytes_per_second = 0.0
        packets_per_second = 0.0

    if packets_sent > 0:
        bytes_per_packet = bytes_sent / packets_sent
    else:
        bytes_per_packet = 0.0

    return {
        # ---------------------------------------------------------
        # Source-side traffic
        # ---------------------------------------------------------
        "bytes_sent": bytes_sent,
        "packets_sent": packets_sent,
        "flow_duration": duration,
        "bytes_per_second": bytes_per_second,
        "packets_per_second": packets_per_second,
        "bytes_per_packet": bytes_per_packet,

        # ---------------------------------------------------------
        # Connection metadata
        # ---------------------------------------------------------
        "source_port": safe_float(row.get("sp")),
        "destination_port": safe_float(row.get("dp")),

        # ---------------------------------------------------------
        # TLS version metadata
        # ---------------------------------------------------------
        "tls_client_version_present": safe_present(
            row.get("tls.cver")
        ),
        "tls_server_version_present": safe_present(
            row.get("tls.sver")
        ),

        # ---------------------------------------------------------
        # Client-side TLS metadata
        # ---------------------------------------------------------
        "tls_extensions_count": safe_len(
            row.get("tls.sext")
        ),
        "tls_cipher_suites_count": safe_len(
            row.get("tls.csg")
        ),
        "tls_compression_count": safe_len(
            row.get("tls.ccs")
        ),
        "tls_client_extensions_count": safe_len(
            row.get("tls.cext")
        ),
        "tls_alpn_count": safe_len(
            row.get("tls.alpn")
        ),

        # ---------------------------------------------------------
        # Directly observable TLS metadata presence
        # ---------------------------------------------------------
        "sni_present": safe_present(
            row.get("tls.sni")
        ),
        "ja3_present": safe_present(
            row.get("tls.ja3")
        ),
        "ja4_present": safe_present(
            row.get("tls.ja4")
        ),
    }