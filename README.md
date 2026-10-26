# Packet Analyzer Robot

A Streamlit interface for extracting packet data from `.pcap` and `.pcapng` captures with PyShark and asking an Ollama model questions about the extracted evidence.

## Requirements

- Python 3.10 or newer
- Wireshark, with `tshark` available on `PATH`
- Ollama running and reachable by the app, with at least one model pulled (required for questions and analysis)

## Run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
ollama pull llama3.1
streamlit run app.py
```

## Run with Docker

Install Docker Desktop (Windows/macOS) or Docker Engine with the Compose plugin (Linux), then start the app from the project directory:

```powershell
docker compose up --build
```

Open `http://localhost:8501`. The image installs `tshark` and runs Streamlit as an unprivileged user. The Compose service connects to Ollama on the Docker host at `http://host.docker.internal:11434`; start Ollama on the host and pull a model before asking questions. To use a different endpoint, set `OLLAMA_BASE_URL` before running Compose. On Linux, make sure the host Ollama service is reachable from Docker; if necessary, configure its bind address and firewall accordingly.

To stop the app, press `Ctrl+C`; use `docker compose down` to remove the container. Uploaded captures are held in the app container's temporary storage and are not added to the image.

The default Ollama endpoint is `http://localhost:11434`. The GUI lists locally available models when Ollama is reachable; otherwise, enter a model name manually. Select a model, edit the system prompt, then ask questions in the Ollama chat tab. Each question is sent to Ollama with PyShark-extracted capture evidence and prior chat turns. There is no local question-answering mode. You can also choose a Wireshark display filter and set the capture-size limit in the sidebar.

The Streamlit server upload ceiling is configured to 4096 MB in `.streamlit/config.toml`; the sidebar lets you choose a lower per-upload ceiling. Deployment platforms and reverse proxies may enforce their own upload limits.

## Analysis and privacy

PyShark uses `tshark` only to parse the capture and extract packet data; it does not answer questions or interpret the traffic. User questions are sent to the selected Ollama model with extracted capture metadata and printable packet payload excerpts. Ollama must be reachable for the app's question-and-answer workflow. Optional IP enrichment uses reverse DNS and unauthenticated RDAP lookups through `rdap.org`; public IP addresses are sent to those services. Private, reserved, and non-routable addresses are not sent to RDAP. Enrichment is off by default.

The Base64 option searches extracted packet text for printable UTF-8 candidates and displays decoded values. It is off by default. Treat capture files and their contents as untrusted data.

The app sends questions as non-streaming Ollama chat requests. Errors returned by Ollama are shown in the interface.
