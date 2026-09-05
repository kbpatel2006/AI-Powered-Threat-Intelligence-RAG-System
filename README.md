##AI-Powered Threat Intelligence RAG System

Cybersecurity knowledge-base and retrieval-augmented generation project that combines MITRE ATT&CK Enterprise data, selected CISA advisories, NIST SP 800-53 controls, and a NIST-to-ATT&CK cross-reference into queryable artifacts.

The project supports two workflows:

1. Build a persistent ChromaDB vector database for local semantic retrieval.
2. Export text files that can be uploaded into Open WebUI's native knowledge-base feature.

## Project Structure

```text
.
├── requirements.txt
├── enterprise-attack.json
├── attack.pdf.html
├── attack.pdf_files/
└── scripts/
    ├── download_attack.py
    ├── downloads_attack1.py
    ├── ingest_attack.py
    ├── query_attack.py
    ├── rag_query.py
    ├── openwebui-convert.py
    ├── parsed_*.json
    ├── chroma_db/
    └── kb_output/
```

## Data Sources

- MITRE ATT&CK Enterprise STIX bundle
- NIST SP 800-53 rev. 5 OSCAL catalog
- Curated CISA advisory chunks for Volt Typhoon, Royal Ransomware, Scattered Spider, GRU Unit 29155, and PRC KV Botnet activity
- Hand-built NIST SP 800-53 to MITRE ATT&CK cross-reference records

## Setup

Use Python 3.13 or a compatible Python 3 version.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

The checked-in `scripts/chroma_db/` and `scripts/kb_output/` directories contain generated artifacts from the current project state. You can regenerate them with the steps below.

## Rebuild Parsed Data

```bash
python scripts/download_attack.py
```

This script downloads or reuses cached source JSON, parses ATT&CK techniques and mitigations, parses NIST 800-53 controls, and writes the `scripts/parsed_*.json` files used by the ingestion/export scripts.

`scripts/downloads_attack1.py` is an earlier, smaller ATT&CK-only downloader/parser retained for reference.

## Build ChromaDB Knowledge Base

```bash
python scripts/ingest_attack.py
```

This creates or refreshes these ChromaDB collections under `scripts/chroma_db/`:

- `attack_kb`
- `attack_mitigations`
- `cisa_kb`
- `nist_800_53`
- `nist_attck_xref`

## Query ChromaDB

Run basic retrieval examples:

```bash
python scripts/query_attack.py
```

Run the simulated incident-report RAG workflow:

```bash
python scripts/rag_query.py
```

`rag_query.py` expects a local Ollama server at `http://localhost:11434` and uses the `phi3` model by default. Install or pull that model before running the script:

```bash
ollama pull phi3
ollama serve
```

## Export for Open WebUI

```bash
python scripts/openwebui-convert.py
```

This writes text files into `scripts/kb_output/`, grouped by source and framework so they can be uploaded into Open WebUI as knowledge-base documents.

## Notes

- Local virtual environments and machine-specific files are intentionally ignored.
- Generated project artifacts are included where they are small enough for normal GitHub storage.
- The ChromaDB embedding model is `all-MiniLM-L6-v2`; keep query and ingestion scripts aligned if you change it.
