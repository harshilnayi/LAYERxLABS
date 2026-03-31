from __future__ import annotations

from pathlib import Path

from .analysis import build_host_summaries, build_protocol_counts, build_top_talkers
from .baseline import build_baseline_profile, compare_against_baseline
from .detectors import run_detectors
from .ingest import load_capture


def analyze_capture(
    capture_path: str | Path,
    top_talkers_limit: int = 5,
    baseline_capture_path: str | Path | None = None,
) -> dict:
    frames = load_capture(capture_path)
    hosts = build_host_summaries(frames)
    protocol_counts = build_protocol_counts(frames)
    top_talkers = build_top_talkers(hosts, limit=top_talkers_limit)

    baseline_profile = None
    baseline_comparison = None
    if baseline_capture_path:
        baseline_frames = load_capture(baseline_capture_path)
        baseline_profile = build_baseline_profile(baseline_frames)
        baseline_comparison = compare_against_baseline(frames, baseline_profile)

    findings = [finding.to_dict() for finding in run_detectors(frames, baseline_profile=baseline_profile)]
    unique_source_macs = sorted({frame.src_mac for frame in frames if frame.src_mac})
    broadcast_frames = sum(1 for frame in frames if frame.is_broadcast)

    return {
        "capture": {
            "source": str(Path(capture_path).resolve()),
            "baseline_source": str(Path(baseline_capture_path).resolve()) if baseline_capture_path else None,
        },
        "overview": {
            "total_frames": len(frames),
            "unique_source_macs": len(unique_source_macs),
            "broadcast_frames": broadcast_frames,
            "findings_count": len(findings),
            "baseline_used": baseline_capture_path is not None,
        },
        "protocols": protocol_counts,
        "top_talkers": top_talkers,
        "hosts": [host.to_dict() for host in hosts],
        "baseline_comparison": baseline_comparison,
        "findings": findings,
    }
