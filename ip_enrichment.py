from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from collections import deque
from typing import Any

import requests

_VT_RATE_WINDOW_SECONDS = 60.0
_VT_MAX_REQUESTS_PER_WINDOW = 3
_vt_request_times: deque[float] = deque()
_vt_request_lock = threading.Lock()


def is_public_ip(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def _wait_for_virustotal_rate_limit() -> None:
    while True:
        with _vt_request_lock:
            now = time.monotonic()
            while _vt_request_times and now - _vt_request_times[0] >= _VT_RATE_WINDOW_SECONDS:
                _vt_request_times.popleft()
            if len(_vt_request_times) < _VT_MAX_REQUESTS_PER_WINDOW:
                _vt_request_times.append(now)
                return
            wait_seconds = _VT_RATE_WINDOW_SECONDS - (now - _vt_request_times[0]) + 0.1
        time.sleep(wait_seconds)


def enrich_ip(address: str) -> dict[str, str]:
    """Return reverse-DNS and public RDAP data without API credentials."""
    result = {"ip": address, "reverse_dns": "", "network": "", "country": "", "asn": "", "error": ""}
    try:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_global:
            result["error"] = "Private, reserved, or non-routable address; public RDAP lookup skipped."
            try:
                result["reverse_dns"] = socket.gethostbyaddr(address)[0]
            except (socket.herror, socket.gaierror, OSError):
                pass
            return result
        try:
            result["reverse_dns"] = socket.gethostbyaddr(address)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass
        response = requests.get(
            f"https://rdap.org/ip/{address}",
            timeout=8,
            headers={"Accept": "application/rdap+json"},
        )
        response.raise_for_status()
        body = response.json()
        result["network"] = str(body.get("name") or body.get("handle") or "")
        result["country"] = str(body.get("country") or "")
        for entity in body.get("entities", []):
            for item in entity.get("publicIds", []):
                if item.get("type", "").lower() == "arin asn":
                    result["asn"] = str(item.get("identifier", ""))
        if not result["asn"]:
            result["asn"] = str(body.get("handle") or "")
    except (ValueError, requests.RequestException, json.JSONDecodeError) as exc:
        result["error"] = str(exc)
    return result


def enrich_ip_virustotal(address: str, api_key: str) -> dict[str, Any]:
    """Return VirusTotal IP reputation data for a globally routable address."""
    parsed = ipaddress.ip_address(address)
    if not parsed.is_global:
        raise ValueError("VirusTotal lookups are only available for public IP addresses.")

    import vt

    with vt.Client(api_key, agent="packet-analyzer-robot", timeout=15) as client:
        _wait_for_virustotal_rate_limit()
        ip_object = client.get_object("/ip_addresses/{}", str(parsed))

    stats = ip_object.get("last_analysis_stats") or {}
    return {
        "vt_reputation": ip_object.get("reputation", ""),
        "vt_network": ip_object.get("network", ""),
        "vt_country": ip_object.get("country", ""),
        "vt_owner": ip_object.get("as_owner", ""),
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_harmless": stats.get("harmless", 0),
        "vt_undetected": stats.get("undetected", 0),
        "vt_error": "",
    }
