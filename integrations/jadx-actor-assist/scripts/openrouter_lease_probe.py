#!/usr/bin/env python3
"""Opt-in OpenRouter management-key preflight and ephemeral child-key smoke.

Runs only on a trusted execution venue with OPENROUTER_MANAGEMENT_KEY.
Never discloses parent/child key; no model or provider inference is performed.
Its use does not register upstream BYOK credentials or guarantee BYOK billing.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
import re
import sys
import urllib.error
import urllib.request

BASE = "https://openrouter.ai"
MAX_USD = 0.25
MAX_MINUTES = 30

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("OPENROUTER_REDIRECT_REJECTED")

class LeaseFailure(Exception):
    pass

class Manager:
    def __init__(self, management_key: str, transport=None):
        if not management_key:
            raise LeaseFailure("MANAGEMENT_CREDENTIAL_NOT_AVAILABLE")
        self._management_key = management_key
        self._transport = transport or urllib.request.build_opener(NoRedirect())

    def _call(self, method: str, path: str, key: str, payload=None):
        if not (path.startswith("/api/v1/") and "?" not in path and
                "\n" not in path and ".." not in path):
            raise LeaseFailure("INVALID_API_PATH")
        body = (json.dumps(payload, separators=(",", ":")).encode("utf-8")
                if payload is not None else None)
        request = urllib.request.Request(
            BASE + path, method=method, data=body, headers={
                "Authorization": "Bearer " + key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            })
        try:
            with self._transport.open(request, timeout=15) as res:
                if res.status < 200 or res.status >= 300:
                    raise LeaseFailure("HTTP_NON_SUCCESS")
                doc = json.loads(res.read(65537))
                if not isinstance(doc, dict):
                    raise LeaseFailure("INVALID_RESPONSE_FORMAT")
                return doc
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError) as exc:
            # No request/response bodies, keys, or server messages leave this layer.
            raise LeaseFailure("OPENROUTER_TRANSPORT_OR_AUTH_FAILED") from None

    def preflight(self) -> dict:
        key = self._call("GET", "/api/v1/key", self._management_key)
        if key.get("data", {}).get("is_management_key") is not True:
            raise LeaseFailure("NOT_A_MANAGEMENT_KEY")
        byok = self._call("GET", "/api/v1/byok", self._management_key)
        rows = byok.get("data", [])
        if not isinstance(rows, list):
            raise LeaseFailure("BYOK_METADATA_INVALID")
        active = sum(isinstance(x, dict) and not x.get("disabled", False)
                     for x in rows)
        # No provider name, credential label or hash in standard output.
        return {"management": "VERIFIED", "byok_registered_active": active,
                "byok_listing_complete": len(rows) < 100}

    @contextmanager
    def lease(self, name: str, limit_usd: float = 0.10, minutes: int = 15):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,60}", name):
            raise LeaseFailure("INVALID_LEASE_NAME")
        if not (0 < limit_usd <= MAX_USD and 1 <= minutes <= MAX_MINUTES):
            raise LeaseFailure("LEASE_BUDGET_OR_DURATION_DENIED")
        expires = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        created = self._call("POST", "/api/v1/keys", self._management_key, {
            "name": name,
            "expires_at": expires.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "include_byok_in_limit": True,
            "limit": limit_usd,
            "limit_reset": None,
        })
        data = created.get("data", {})
        child = created.get("key")
        lease_hash = data.get("hash")
        if not isinstance(lease_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", lease_hash):
            raise LeaseFailure("CHILD_KEY_HASH_MISSING_OR_INVALID")
        try:
            if not isinstance(child, str) or not child.startswith("sk-or-"):
                raise LeaseFailure("CHILD_KEY_NOT_RETURNED")
            if data.get("include_byok_in_limit") is not True:
                raise LeaseFailure("CHILD_BYOK_LIMIT_NOT_ENABLED")
            if data.get("limit") is None or float(data["limit"]) > limit_usd + 0.0000001:
                raise LeaseFailure("CHILD_SPEND_LIMIT_NOT_ENFORCED")
            yield child
        finally:
            revoked = self._call("DELETE", "/api/v1/keys/" + lease_hash,
                                 self._management_key, {})
            if revoked.get("deleted") is not True:
                raise LeaseFailure("CHILD_REVOCATION_NOT_CONFIRMED")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preflight", "ephemeral-auth-smoke"))
    args = parser.parse_args()
    try:
        manager = Manager(os.environ.get("OPENROUTER_MANAGEMENT_KEY", ""))
        status = manager.preflight()
        if args.operation == "ephemeral-auth-smoke":
            if os.environ.get("AAR_ALLOW_CHILD_KEY_PROBE") != "true":
                raise LeaseFailure("CREATION_REQUIRES_EXPLICIT_ENV_APPROVAL")
            with manager.lease("aar-jadx-smoke") as child:
                # Child credentials must prove non-management and scoped allowance.
                detail = manager._call("GET", "/api/v1/key", child)
                state = detail.get("data", {})
                if state.get("is_management_key") is True:
                    raise LeaseFailure("CHILD_HAS_MANAGEMENT_AUTHORITY")
                if state.get("include_byok_in_limit") is not True:
                    raise LeaseFailure("CHILD_POLICY_DRIFT")
            status["ephemeral_child"] = "CREATED_PROBED_AND_REVOKED"
        print(json.dumps(status, sort_keys=True))
        return 0
    except LeaseFailure as ex:
        print(json.dumps({"status": str(ex)}, sort_keys=True), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
