from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import re
import socket
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pandas as pd
import pyshark
import requests
import streamlit as st

APP_TITLE = "Packet Analyzer Robot"
DEFAULT_SYSTEM_PROMPT = """You are a network traffic analyst. Analyze only the packet-capture evidence provided. Separate observed facts from hypotheses, cite packet or stream identifiers where available, and do not claim maliciousness without supporting evidence. Do not invent packet contents or external context."""
BASE64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/])")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

st.set_page_config(page_title=APP_TITLE, page_icon="📡", layout="wide")
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
    :root { --ink: #17221f; --muted: #61706b; --paper: #f4f5f0; --panel: #fffefa; --line: #d9ded6; --signal: #d94f32; --green: #176b55; }
    html, body, [class*="css"] { font-family: 'Manrope', sans-serif; color: var(--ink); }
    .stApp { background: radial-gradient(ellipse at 92% 0%, #e2eee7 0, transparent 31%), var(--paper); }
    h1, h2, h3 { letter-spacing: 0 !important; }
    h1 { font-size: 2.2rem !important; font-weight: 800 !important; }
    .eyebrow { color: var(--signal); font: 500 .75rem 'DM Mono', monospace; text-transform: uppercase; }
    .lede { color: var(--muted); margin-top: -.5rem; }
    .metric-label { color: var(--muted); font: 500 .72rem 'DM Mono', monospace; text-transform: uppercase; }
    code, pre, .stCode { font-family: 'DM Mono', monospace !important; }
    div[data-testid="stMetric"] { background: var(--panel); border: 1px solid var(--line); padding: .8rem 1rem; border-radius: 5px; }
    div[data-testid="stMetricLabel"] { color: var(--muted); }
    .stTabs [data-baseweb="tab-list"] { gap: 1rem; }
    section[data-testid="stSidebar"] { background: #edf0e9; border-right: 1px solid var(--line); }
    </style>
    """,
    unsafe_allow_html=True,
)


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
    """Read a pcap or pcapng capture with tshark through PyShark."""
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


def enrich_ip(address: str) -> dict[str, str]:
    """Return local reverse-DNS and RDAP data; no API key or account is used."""
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
        response = requests.get(f"https://rdap.org/ip/{address}", timeout=8, headers={"Accept": "application/rdap+json"})
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


def ollama_models(base_url: str) -> list[str]:
    response = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=5)
    response.raise_for_status()
    return [item["name"] for item in response.json().get("models", []) if item.get("name")]


def ask_ollama(
    base_url: str,
    model: str,
    system_prompt: str,
    user_prompt: str = "",
    conversation: list[dict[str, str]] | None = None,
) -> str:
    messages = [{"role": "system", "content": system_prompt}]
    if conversation is None:
        messages.append({"role": "user", "content": user_prompt})
    else:
        messages.extend(conversation)
    response = requests.post(
        f"{base_url.rstrip('/')}/api/chat",
        json={"model": model, "stream": False, "messages": messages},
        timeout=None,
    )
    response.raise_for_status()
    return str(response.json().get("message", {}).get("content", ""))


def analysis_context(records: list[dict[str, Any]], streams: dict[str, str], include_base64: bool) -> str:
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


st.sidebar.markdown('<div class="eyebrow">Analysis settings</div>', unsafe_allow_html=True)
st.sidebar.header("Capture & model")
max_mb = st.sidebar.number_input("Maximum upload size (MB)", min_value=1, max_value=4096, value=256, step=16, help="Files above this limit are rejected before analysis.")
uploaded_file = st.sidebar.file_uploader("Packet capture", type=["pcap", "pcapng", "cap"], help="Select a .pcap or .pcapng file.")
ollama_url = st.sidebar.text_input(
    "Ollama URL",
    value=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
)
model_options: list[str] = []
model_error = ""
try:
    model_options = ollama_models(ollama_url)
except requests.RequestException as exc:
    model_error = str(exc)
if model_options:
    selected_model = st.sidebar.selectbox("Model", model_options)
else:
    selected_model = st.sidebar.text_input("Model name", placeholder="e.g. llama3.1")
    if model_error:
        st.sidebar.caption("Could not load model list: " + model_error)
display_filter = st.sidebar.text_input("Wireshark display filter", placeholder="e.g. http or tcp.port == 443")
include_base64 = st.sidebar.checkbox("Find and decode Base64 candidates", value=False, help="Only decodes printable UTF-8 candidates in extracted packet text; encoded content is sent to Ollama with your question.")
enrich_enabled = st.sidebar.checkbox("Enrich IP addresses via reverse DNS + RDAP", value=False)
system_prompt = st.sidebar.text_area("System prompt", value=DEFAULT_SYSTEM_PROMPT, height=170)

st.markdown('<div class="eyebrow">SOC / PCAP WORKBENCH</div>', unsafe_allow_html=True)
st.title(APP_TITLE)
st.markdown('<p class="lede">Inspect packet captures, follow TCP conversations, and ask a local Ollama model to explain the evidence.</p>', unsafe_allow_html=True)

if not uploaded_file:
    st.info("Choose a pcap or pcapng file in the sidebar to begin.")
    st.stop()

if uploaded_file.size > int(max_mb) * 1024 * 1024:
    st.error(f"File is {uploaded_file.size / (1024 * 1024):.1f} MB, above the configured {int(max_mb)} MB limit.")
    st.stop()

if (
    st.session_state.get("capture_name") != uploaded_file.name
    or st.session_state.get("capture_filter") != display_filter
):
    st.session_state.pop("records", None)
    st.session_state.pop("packets", None)
    st.session_state.ollama_chat = []
    st.session_state.capture_name = uploaded_file.name
    st.session_state.capture_filter = display_filter

if "records" not in st.session_state:
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded_file.name).suffix) as temp_file:
            temp_file.write(uploaded_file.getbuffer())
            capture_path = temp_file.name
        try:
            with st.spinner("Reading capture with tshark..."):
                records = parse_capture(capture_path, display_filter)
        finally:
            Path(capture_path).unlink(missing_ok=True)
        st.session_state.records = records
    except Exception as exc:
        st.error(f"Capture parsing failed: {exc}")
        st.caption("PyShark requires Wireshark/tshark to be installed and available on PATH.")
        st.stop()

records = st.session_state.records
packets = pd.DataFrame(records)
streams = build_streams(records)
if not records:
    st.warning("No packets matched the capture or display filter.")
    st.stop()

metric_cols = st.columns(4)
metric_cols[0].metric("Packets", f"{len(records):,}")
metric_cols[1].metric("TCP streams", f"{len(streams):,}")
metric_cols[2].metric("Unique hosts", f"{packets['host'].replace('', pd.NA).nunique() if 'host' in packets else 0:,}")
metric_cols[3].metric("Protocols", f"{packets['protocol'].nunique():,}")

packet_tab, streams_tab, domains_tab, enrich_tab, analysis_tab = st.tabs(["Packets", "TCP streams", "HTTP / domains", "IP enrichment", "Ollama analysis"])
with packet_tab:
    visible = packets.drop(columns=["payload_text", "payload_hex"], errors="ignore")
    page_size = st.selectbox("Rows per page", [100, 500, 1000, 5000], index=1)
    page_count = max((len(visible) + page_size - 1) // page_size, 1)
    page_number = st.number_input("Page", min_value=1, max_value=page_count, value=1, step=1)
    start = (int(page_number) - 1) * page_size
    st.dataframe(visible.iloc[start : start + page_size], width="stretch", hide_index=True, height=480)
    st.caption(f"Showing {start + 1:,}-{min(start + page_size, len(visible)):,} of {len(visible):,} packets.")
    st.download_button("Download packet summary CSV", data=visible.to_csv(index=False), file_name="packet-summary.csv", mime="text/csv")

with streams_tab:
    if not streams:
        st.info("No TCP streams found.")
    else:
        stream_id = st.selectbox("TCP stream", list(streams))
        content = streams[stream_id]
        st.code(content, language="text", wrap_lines=True)
        if st.button("Explain this stream", key=f"explain-stream-{stream_id}", disabled=not selected_model):
            stream_prompt = (
                "Explain the sequence of events in this TCP stream using only the provided evidence. "
                "Identify each endpoint, notable requests or responses, and uncertainty.\n\n"
                + content
            )
            try:
                with st.spinner(f"Asking {selected_model} about stream {stream_id}..."):
                    answer = ask_ollama(ollama_url, selected_model, system_prompt, stream_prompt)
                st.markdown(answer)
            except requests.RequestException as exc:
                response_text = exc.response.text if exc.response is not None else ""
                st.error(response_text or str(exc))
            except Exception as exc:
                st.error(str(exc))

with domains_tab:
    web_rows = packets[packets["host"].astype(bool) | packets["url"].astype(bool)]
    if web_rows.empty:
        st.info("No HTTP host headers, TLS server names, DNS query names, or URLs were identified in the decoded packets.")
    else:
        st.dataframe(web_rows[["packet", "src", "dst", "protocol", "host", "url"]], width="stretch", hide_index=True)
    extra_urls = sorted({match.rstrip(".,);]") for row in records for match in URL_PATTERN.findall(row.get("payload_text", ""))})
    if extra_urls:
        st.markdown("**URLs found in decoded payload text**")
        st.dataframe(pd.DataFrame({"URL": extra_urls}), width="stretch", hide_index=True)

with enrich_tab:
    ip_addresses = sorted({value for row in records for value in (row["src"], row["dst"]) if value})
    if not enrich_enabled:
        st.info("Enable IP enrichment in the sidebar to perform reverse DNS and public RDAP lookups. Public lookups only run for globally routable addresses.")
    elif st.button("Enrich observed IPs", type="primary"):
        enriched: list[dict[str, str]] = []
        progress = st.progress(0)
        for index, address in enumerate(ip_addresses):
            enriched.append(enrich_ip(address))
            progress.progress((index + 1) / max(len(ip_addresses), 1))
        st.dataframe(pd.DataFrame(enriched), width="stretch", hide_index=True)
        st.caption("RDAP queries disclose the selected public IP addresses to rdap.org. Private, reserved, and non-routable addresses are not sent.")

with analysis_tab:
    st.write("Ask a question about this capture. Each question is sent to the selected Ollama model together with extracted packet evidence and this conversation.")
    for message in st.session_state.ollama_chat:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    question = st.chat_input("Ask Ollama about this capture...", disabled=not selected_model)
    if question:
        with st.chat_message("user"):
            st.markdown(question)
        context = analysis_context(records, streams, include_base64)
        conversation = [
            *st.session_state.ollama_chat[-6:],
            {
                "role": "user",
                "content": (
                    "A packet capture is already loaded. Answer the question using the capture evidence below; "
                    "do not ask the user to upload or paste it again. If the evidence contains no matching traffic, "
                    "say so and cite what was checked.\n\n"
                    f"Question: {question}\n\nCapture evidence (JSON):\n{context}"
                ),
            },
        ]
        try:
            with st.spinner(f"Asking {selected_model}..."):
                answer = ask_ollama(
                    ollama_url,
                    selected_model,
                    system_prompt,
                    conversation=conversation,
                )
            with st.chat_message("assistant"):
                st.markdown(answer)
            st.session_state.ollama_chat.extend([
                {"role": "user", "content": question},
                {"role": "assistant", "content": answer},
            ])
        except requests.RequestException as exc:
            response_text = exc.response.text if exc.response is not None else ""
            st.error(response_text or str(exc))
        except Exception as exc:
            st.error(str(exc))
    if include_base64:
        candidates = [
            {"packet": row["packet"], **candidate}
            for row in records
            for candidate in decode_base64_candidates(row.get("payload_text", ""))
        ]
        if candidates:
            st.markdown("**Base64 candidates**")
            st.dataframe(pd.DataFrame(candidates), width="stretch", hide_index=True)
        else:
            st.caption("No printable Base64 candidates found in the extracted text fields.")
