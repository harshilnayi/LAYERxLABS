from __future__ import annotations

from pathlib import Path

from .analysis import build_host_summaries, build_protocol_counts, build_top_talkers
from .detectors import run_phase1_detectors
from .ingest import load_capture


def analyze_capture(capture_path: str | Path, top_talkers_limit: int = 5) -> dict:
    frames = load_capture(capture_path)
    hosts = build_host_summaries(frames)
    findings = [finding.to_dict() for finding in run_phase1_detectors(frames)]
    protocol_counts = build_protocol_counts(frames)
    top_talkers = build_top_talkers(hosts, limit=top_talkers_limit)

    unique_source_macs = sorted({frame.src_mac for frame in frames if frame.src_mac})
    broadcast_frames = sum(1 for frame in frames if frame.is_broadcast)

    return {
        "capture": {
            "source": str(Path(capture_path).resolve()),
        },
        "overview": {
            "total_frames": len(frames),
            "unique_source_macs": len(unique_source_macs),
            "broadcast_frames": broadcast_frames,
            "findings_count": len(findings),
        },
        "protocols": protocol_counts,
        "top_talkers": top_talkers,
        "hosts": [host.to_dict() for host in hosts],
        "findings": findings,
    }
