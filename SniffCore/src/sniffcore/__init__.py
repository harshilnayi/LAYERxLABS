"""SniffCore package."""

from __future__ import annotations

import logging
import os

# SniffCore works on capture files that already exist on disk, so it should not
# ask Scapy to initialize libpcap-backed live sockets during import.
os.environ["SCAPY_USE_LIBPCAP"] = "no"
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from .pipeline import analyze_capture

__all__ = ["analyze_capture"]
