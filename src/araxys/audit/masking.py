"""PII masking for audit log entries.

Provides recursive masking of sensitive fields before they are
written to the audit log, ensuring plaintext PII is never persisted.
"""

from __future__ import annotations

from typing import Any


def mask_pii(
    data: Any,
    pii_fields: list[str],
    mask_char: str = "*",
) -> Any:
    """Recursively mask PII field values in ``data``.

    Parameters
    ----------
    data:
        The data to mask. Typically a dict (e.g. an audit entry serialised
        to a dict), but any value is accepted.
    pii_fields:
        Field names whose values should be masked.
    mask_char:
        Character used to build the replacement string.

    Returns
    -------
    A new value with PII fields masked. The original ``data`` is never
    mutated.
    """
    if not isinstance(data, dict):
        return data

    result: dict[str, Any] = {}
    for key, value in data.items():
        masked_key = key
        if isinstance(value, dict):
            result[masked_key] = mask_pii(value, pii_fields, mask_char)
        elif isinstance(value, list):
            result[masked_key] = [
                mask_pii(item, pii_fields, mask_char)
                if isinstance(item, (dict, list))
                else item
                for item in value
            ]
        elif key in pii_fields:
            result[masked_key] = mask_char * 3
        else:
            result[masked_key] = value
    return result
