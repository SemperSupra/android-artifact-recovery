"""Fail-closed, metadata-only classifier for JADX exit/completeness evidence.

An exit code of zero establishes process success, NOT exhaustive class coverage.
Last emitted progress is an observation, never a completeness denominator.
"""
from __future__ import annotations
import re

_EXIT = re.compile(r'^jadx_returncode=(-?\d+)\s*$', re.M)
_ERRORS = re.compile(r'finished with errors, count:\s*(\d+)', re.I)
_PROGRESS = re.compile(r'progress:\s*(\d+)\s+of\s+(\d+)\s+\((\d+)%\)')


def qualify_jadx_log(log: str) -> dict:
    exits = list(_EXIT.finditer(log))
    reported_errors = list(_ERRORS.finditer(log))
    progress = list(_PROGRESS.finditer(log))
    exit_code = int(exits[-1].group(1)) if exits else None
    error_count = int(reported_errors[-1].group(1)) if reported_errors else None
    last_progress = (
        {
            'last_observed_processed': int(progress[-1].group(1)),
            'last_observed_total': int(progress[-1].group(2)),
            'last_reported_percent': int(progress[-1].group(3)),
        }
        if progress else None
    )
    if exit_code is None:
        verdict = 'MISSING_JADX_EXIT_CODE'
    elif exit_code != 0 or (error_count is not None and error_count > 0):
        verdict = 'JADX_RETURNED_ERRORS_PARTIAL_EVIDENCE'
    else:
        verdict = 'JADX_EXIT_ZERO_COVERAGE_UNVERIFIED'
    return {
        'status': verdict,
        'exit_code': exit_code,
        'reported_error_count': error_count,
        'last_progress_log_only': last_progress,
        'full_class_coverage_verified': False,
        'claim_boundary': 'JADX progress/log counters are observations; they do not independently prove coverage of every class or feature.',
    }
