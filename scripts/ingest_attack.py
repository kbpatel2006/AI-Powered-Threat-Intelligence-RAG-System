"""
Embeds all five parsed JSON files into persistent ChromaDB collections:

  Collection:          Source file:                       Purpose:
  attack_kb           parsed_techniques.json             TTP definitions
  attack_mitigations  parsed_mitigations.json            ATT&CK mitigations
  cisa_kb             parsed_cisa.json                   CISA advisory chunks
  nist_800_53         parsed_nist_800_53.json            NIST 800-53 controls
  nist_attck_xref     parsed_nist_attck_crossref.json    NIST ↔ ATT&CK bridge
"""

import json
import sys
from pathlib import Path
from tqdm import tqdm
import chromadb
from chromadb.utils import embedding_functions

# CONFIGURATION

BASE_DIR        = Path(__file__).resolve().parent
CHROMA_PATH     = BASE_DIR / "chroma_db"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"   # must stay consistent with rag_query.py
BATCH_SIZE      = 50

# Maps collection_name to source JSON file
INGESTION_PLAN = {
    "attack_kb":          BASE_DIR / "parsed_techniques.json",
    "attack_mitigations": BASE_DIR / "parsed_mitigations.json",
    "cisa_kb":            BASE_DIR / "parsed_cisa.json",
    "nist_800_53":        BASE_DIR / "parsed_nist_800_53.json",
    "nist_attck_xref":    BASE_DIR / "parsed_nist_attck_crossref.json",  # NEW — NIST↔ATT&CK bridge
}

# DOCUMENT BUILDERS
# Each function takes one parsed record and returns
# (doc_id, document_text, metadata_dict)

def build_technique_doc(t: dict) -> tuple[str, str, dict]:
    doc = (
        f"Technique: {t['name']}\n"
        f"ID: {t['technique_id']}\n"
        f"Tactics: {t['tactics']}\n"
        f"Platforms: {t['platforms']}\n"
        f"Description: {t['description']}\n"
        f"Detection: {t['detection']}"
    )
    meta = {
        "technique_id":    t["technique_id"],
        "name":            t["name"],
        "tactics":         t["tactics"],
        "platforms":       t["platforms"],
        "is_subtechnique": str(t.get("is_subtechnique", False)),
        "source":          "MITRE ATT&CK Enterprise",
    }
    return t["technique_id"], doc, meta


def build_mitigation_doc(m: dict) -> tuple[str, str, dict]:
    doc = (
        f"Mitigation: {m['name']}\n"
        f"ID: {m['mitigation_id']}\n"
        f"Applies to techniques: {m['technique_ids']}\n"
        f"Description: {m['description']}"
    )
    meta = {
        "mitigation_id":  m["mitigation_id"],
        "name":           m["name"],
        "technique_ids":  m["technique_ids"],
        "source":         "MITRE ATT&CK Mitigations",
    }
    return m["mitigation_id"], doc, meta


def build_cisa_doc(c: dict) -> tuple[str, str, dict]:
    # technique_ids is now a structured list in CISA chunks
    technique_ids = c.get("technique_ids", [])
    tech_str = ", ".join(technique_ids) if technique_ids else "N/A"

    doc = (
        f"Advisory: {c['advisory_id']} — {c['title']}\n"
        f"Date: {c['date']}\n"
        f"Threat Actor: {c.get('threat_actor', 'Unknown')}\n"
        f"Section: {c['section']}\n"
        f"ATT&CK Technique IDs: {tech_str}\n"
        f"Content: {c['content']}"
    )
    # Unique ID: advisory_id + section
    doc_id = c["advisory_id"] + "_" + c["section"].replace(" ", "_")[:40]
    meta = {
        "advisory_id":   c["advisory_id"],
        "title":         c["title"],
        "date":          c["date"],
        "section":       c["section"],
        "threat_actor":  c.get("threat_actor", "Unknown"),
        "technique_ids": tech_str,   # stored as comma string (ChromaDB scalar)
        "source":        "CISA Advisory",
    }
    return doc_id, doc, meta


def build_nist_doc(n: dict) -> tuple[str, str, dict]:
    doc = (
        f"NIST 800-53 Control: {n['control_id']} — {n['title']}\n"
        f"Family: {n['family_id']} ({n['family_title']})\n"
        f"Framework: {n['framework']}\n"
        f"Description: {n['description']}"
    )
    if n.get("enhancements"):
        doc += f"\nEnhancements: {n['enhancements']}"
    meta = {
        "control_id":   n["control_id"],
        "title":        n["title"],
        "family_id":    n["family_id"],
        "family_title": n["family_title"],
        "source":       "NIST SP 800-53 rev5",
    }
    return n["control_id"], doc, meta


def build_crossref_doc(x: dict) -> tuple[str, str, dict]:
    """
    Builder for NIST 800-53 ↔ ATT&CK cross-reference records.
    The document text is written so a semantic query like
    "NIST control for credential dumping" or "ATT&CK mitigation for T1003"
    retrieves the right mapping.
    """
    nist_controls     = ", ".join(x.get("nist_controls", []))
    attck_mitigations = ", ".join(x.get("attck_mitigations", []))
    technique_ids     = ", ".join(x.get("technique_ids", []))

    doc = (
        f"NIST↔ATT&CK Mapping: {x['mapping_id']} — {x['category']}\n"
        f"NIST 800-53 Controls: {nist_controls}\n"
        f"ATT&CK Mitigations: {attck_mitigations}\n"
        f"Addressed Techniques: {technique_ids}\n"
        f"Rationale: {x['rationale']}"
    )
    meta = {
        "mapping_id":         x["mapping_id"],
        "category":           x["category"],
        "nist_controls":      nist_controls,       # comma string
        "attck_mitigations":  attck_mitigations,   # comma string
        "technique_ids":      technique_ids,        # comma string
        "source":             "NIST 800-53 ↔ ATT&CK Cross-Reference",
    }
    return x["mapping_id"], doc, meta


# Maps collection name to builder function
BUILDERS = {
    "attack_kb":          build_technique_doc,
    "attack_mitigations": build_mitigation_doc,
    "cisa_kb":            build_cisa_doc,
    "nist_800_53":        build_nist_doc,
    "nist_attck_xref":    build_crossref_doc,     
}


# INGEST ONE COLLECTION

def ingest_collection(
    client: chromadb.PersistentClient,
    ef,
    collection_name: str,
    json_file: str,
) -> int:
    # Load records
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            records = json.load(f)
    except FileNotFoundError:
        print(f"{json_file} not found — run download_attack.py first")
        return 0

    # Wipe and recreate for clean ingest
    try:
        client.delete_collection(collection_name)
    except Exception:
        pass
    collection = client.create_collection(
        name=collection_name,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    builder = BUILDERS[collection_name]
    ids, docs, metas = [], [], []

    for record in tqdm(records, desc=f"  Embedding {collection_name}", unit="doc"):
        try:
            doc_id, doc_text, metadata = builder(record)
        except Exception as e:
            continue

        ids.append(str(doc_id))
        docs.append(doc_text)
        metas.append(metadata)

        if len(ids) >= BATCH_SIZE:
            collection.upsert(ids=ids, documents=docs, metadatas=metas)
            ids, docs, metas = [], [], []

    if ids:
        collection.upsert(ids=ids, documents=docs, metadatas=metas)

    total = collection.count()
    print(f"{collection_name}: {total} documents ingested\n")
    return total


# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────

def main():
    print("Multi-Framework ChromaDB Ingestion Pipeline")

    print(f"Initialising persistent ChromaDB at {CHROMA_PATH}")
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    ef     = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )
    print(f"Embedding model: {EMBEDDING_MODEL}\n")

    totals = {}
    for collection_name, json_file in INGESTION_PLAN.items():
        print(f"── {collection_name.upper()} ({'─' * (40 - len(collection_name))})")
        totals[collection_name] = ingest_collection(
            client, ef, collection_name, json_file
        )

    print("  Ingestion complete — collections in ./chroma_db/")
    for name, count in totals.items():
        print(f"  • {name:<22} {count:>4} documents")
    print("\nRun rag_query.py to query across all five frameworks\n")


if __name__ == "__main__":
    main()
