from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

APP_TITLE = "Packet Analyzer Robot"
from ip_enrichment import enrich_ip
from ollama_client import DEFAULT_SYSTEM_PROMPT, ask as ask_ollama, list_models as ollama_models
from packet_analysis import (
    URL_PATTERN,
    analysis_context,
    build_streams,
    decode_base64_candidates,
    parse_capture,
)

st.set_page_config(page_title=APP_TITLE, layout="wide")

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
