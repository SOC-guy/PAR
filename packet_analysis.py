from __future__ import annotations

import base64
import binascii
import json
import re
from collections import Counter, defaultdict
from typing import Any

import pyshark

BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/])")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def decode_base64_candidates(text: str) -> list[dict[str, str]]:
    """Decode printable, plausible Base64 candidates found in a text payload."""
    results: list[dict[str, str]] = []
    seen: set[str] = set()
    for candidate in BASE64_PATTERN.findall(text):
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
            rendered = decoded.decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if len(rendered) < 4 or not rendered.isprintable() or candidate in seen:
            continue
        seen.add(candidate)
        results.append({"encoded": candidate, "decoded": rendered})
    return results


def _field(layer: Any, name: str, default: str = "") -> str:
    try:
        value = getattr(layer, name)
        return str(value) if value is not None else default
    except (AttributeError, TypeError):
        return default


def _packet_summary(packet: Any, index: int) -> dict[str, Any]:
    layers = {layer.layer_name.lower(): layer for layer in packet.layers}
    ip_layer = layers.get("ip") or layers.get("ipv6")
    transport = layers.get("tcp") or layers.get("udp")
    source = _field(ip_layer, "src") if ip_layer else ""
    destination = _field(ip_layer, "dst") if ip_layer else ""
    protocol = transport.layer_name.upper() if transport else (packet.highest_layer or "OTHER")
    tcp_stream = _field(layers.get("tcp"), "stream") if "tcp" in layers else ""
    udp_stream = _field(layers.get("udp"), "stream") if "udp" in layers else ""
    info_parts = []
    if transport:
        for key in ("srcport", "dstport", "flags", "len"):
            value = _field(transport, key)
            if value:
                info_parts.append(f"{key}={value}")
    http = layers.get("http")
    tls = layers.get("tls") or layers.get("ssl")
    dns = layers.get("dns")
    host = _field(http, "host") if http else ""
    uri = _field(http, "request_uri") if http else ""
    http_method = _field(http, "request_method") if http else ""
    http_status = _field(http, "response_code") if http else ""
    http_content_type = _field(http, "content_type") if http else ""
    if host and uri:
        url = f"http://{host}{uri}"
    elif uri.startswith("http://") or uri.startswith("https://"):
        url = uri
    else:
        url = ""
    if tls:
        host = host or _field(tls, "handshake_extensions_server_name")
    if dns:
        host = host or _field(dns, "qry_name")
    payload_text = ""
    for layer_name in ("http", "dns", "data", "ftp", "smtp", "tls"):
        layer = layers.get(layer_name)
        if layer:
            try:
                payload_text += " " + str(layer)
            except Exception:
                pass
    try:
        raw_packet = packet.get_raw_packet()
        printable_runs = re.findall(rb"[\x20-\x7e]{8,}", raw_packet)
        payload_text += " " + " ".join(run.decode("ascii") for run in printable_runs)
    except (AttributeError, TypeError, ValueError):
        pass
    raw_hex = ""
    try:
        raw_hex = _field(layers.get("tcp") or layers.get("udp") or layers.get("data"), "payload")
    except Exception:
        pass
    return {
        "packet": index,
        "time": str(getattr(packet, "sniff_time", "")),
        "src": source,
        "dst": destination,
        "protocol": protocol,
        "src_port": _field(transport, "srcport") if transport else "",
        "dst_port": _field(transport, "dstport") if transport else "",
        "tcp_stream": tcp_stream,
        "udp_stream": udp_stream,
        "host": host,
        "url": url,
        "http_method": http_method,
        "http_status": http_status,
        "http_content_type": http_content_type,
        "info": " ".join(info_parts),
        "payload_text": payload_text.strip(),
        "payload_hex": raw_hex,
    }


def parse_capture(capture_path: str, display_filter: str = "") -> list[dict[str, Any]]:
    """Parse a pcap or pcapng file with PyShark and extract packet evidence."""
    records: list[dict[str, Any]] = []
    capture = pyshark.FileCapture(
        capture_path,
        display_filter=display_filter or None,
        keep_packets=False,
        use_json=True,
        include_raw=True,
    )
    try:
        for index, packet in enumerate(capture, start=1):
            records.append(_packet_summary(packet, index))
    finally:
        capture.close()
    return records


def build_streams(records: list[dict[str, Any]]) -> dict[str, str]:
    streams: dict[str, list[str]] = defaultdict(list)
    for row in records:
        stream_id = row.get("tcp_stream")
        if not stream_id:
            continue
        direction = f"{row['src']}:{row['src_port']} -> {row['dst']}:{row['dst_port']}"
        bits = [f"packet {row['packet']} ({direction})"]
        if row.get("host"):
            bits.append(f"host={row['host']}")
        if row.get("url"):
            bits.append(f"url={row['url']}")
        if row.get("http_method"):
            bits.append(f"http_method={row['http_method']}")
        if row.get("http_status"):
            bits.append(f"http_status={row['http_status']}")
        if row.get("http_content_type"):
            bits.append(f"content_type={row['http_content_type']}")
        if row.get("info"):
            bits.append(row["info"])
        if row.get("payload_text"):
            bits.append(row["payload_text"][:600])
        elif row.get("payload_hex"):
            bits.append(f"payload_hex={row['payload_hex'][:300]}")
        streams[str(stream_id)].append(" | ".join(bits))
    return {stream_id: "\n".join(lines) for stream_id, lines in streams.items()}


def analysis_context(
    records: list[dict[str, Any]],
    streams: dict[str, str],
    include_base64: bool,
) -> str:
    """Build bounded, structured packet evidence for an Ollama request."""
    protocol_counts = Counter(row["protocol"] for row in records)
    endpoints = Counter(value for row in records for value in (row["src"], row["dst"]) if value)
    urls = sorted({row["url"] for row in records if row["url"]})
    hosts = sorted({row["host"] for row in records if row["host"]})
    http_packets = [
        {
            "packet": row["packet"],
            "tcp_stream": row["tcp_stream"],
            "src": row["src"],
            "src_port": row["src_port"],
            "dst": row["dst"],
            "dst_port": row["dst_port"],
            "method": row["http_method"],
            "url": row["url"],
            "status": row["http_status"],
            "content_type": row["http_content_type"],
        }
        for row in records
        if row["http_method"] or row["http_status"]
    ]
    context: dict[str, Any] = {
        "packet_count": len(records),
        "protocol_counts": protocol_counts,
        "top_endpoints": endpoints.most_common(30),
        "hosts": hosts[:200],
        "urls": urls[:200],
        "http_packet_count": len(http_packets),
        "http_packets": http_packets[:100],
        "tcp_streams": {key: value[:2000] for key, value in list(streams.items())[:20]},
        "packet_examples": [
            {
                key: (row[key][:300] if key == "payload_text" else row[key])
                for key in ("packet", "time", "src", "dst", "protocol", "src_port", "dst_port", "info", "payload_text")
            }
            for row in records[:50]
        ],
    }
    if include_base64:
        context["base64_candidates"] = [
            {"packet": row["packet"], **candidate}
            for row in records
            for candidate in decode_base64_candidates(row.get("payload_text", ""))
        ][:300]
    return json.dumps(context, default=dict, ensure_ascii=True)
