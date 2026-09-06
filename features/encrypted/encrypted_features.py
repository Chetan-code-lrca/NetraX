import ast
import math
from typing import Any


def _is_missing(value: Any) -> bool:
    if value is None:
        return True

    if isinstance(value, float):
        return math.isnan(value)

    if isinstance(value, str):
        return not value.strip()

    return False


def safe_len(value: Any) -> int:
    """Safely count elements in list-like metadata."""

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
    """Return 1 when a metadata field is present."""

    return 0 if _is_missing(value) else 1


def safe_float(value: Any) -> float:
    """Convert value to float safely."""

    try:
        if _is_missing(value):
            return 0.0

        return float(value)

    except (TypeError, ValueError):
        return 0.0


def extract_encrypted_features(row) -> dict[str, float]:
    """
    Extract one-way observable encrypted-traffic features.

    Deliberately excluded:
        br              reverse bytes
        pr              reverse packets
        tls.ja3s        server-side JA3
        tls.ja4s        server-side JA4
        decrypted data
        application payload
        server response semantics
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
        # Source-side traffic
        "bytes_sent": bytes_sent,
        "packets_sent": packets_sent,
        "flow_duration": duration,
        "bytes_per_second": bytes_per_second,
        "packets_per_second": packets_per_second,
        "bytes_per_packet": bytes_per_packet,

        # Connection metadata
        "destination_port": safe_float(row.get("dp")),

        # TLS version presence
        "tls_client_version_present": safe_present(
            row.get("tls.cver")
        ),
        "tls_server_version_present": safe_present(
            row.get("tls.sver")
        ),

        # Client-observable TLS metadata
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

        # Metadata presence
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
