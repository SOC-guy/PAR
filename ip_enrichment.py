from __future__ import annotations

import ipaddress
import json
import socket

import requests


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
