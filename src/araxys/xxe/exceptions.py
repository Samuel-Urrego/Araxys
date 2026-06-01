"""XXEError exception for XML external entity attack detection."""

from __future__ import annotations

from araxys.core.exceptions import AraxysError


class XXEError(AraxysError):
    """Raised when an XXE attack is detected by the scanner or middleware.

    Parameters
    ----------
    detection_type:
        The type of XXE detected (e.g. ``"dtd"``, ``"entity"``,
        ``"external_entity"``, ``"entity_expansion"``).
    detail:
        Human-readable description of the detection.
    source_ip:
        Optional source IP address for audit logging.
    """

    def __init__(
        self,
        detection_type: str,
        detail: str = "",
        source_ip: str | None = None,
    ) -> None:
        self.detection_type = detection_type
        self.detail = detail
        self.source_ip = source_ip

        parts = [f"XXE detected: {detection_type}"]
        if detail:
            parts.append(detail)
        if source_ip:
            parts.append(f"from {source_ip}")

        super().__init__(" — ".join(parts))
