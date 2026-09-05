"""
Converts the five parsed JSON files into plain-text files formatted for Open WebUI's native RAG Knowledge Base.

OUTPUT FILES:
  kb_output/
    cisa_AA23-144A.txt          Volt Typhoon advisory
    cisa_AA24-038A.txt          PRC KV Botnet advisory
    cisa_AA23-061A.txt          Royal Ransomware advisory
    cisa_AA23-320A.txt          Scattered Spider advisory
    cisa_AA24-190A.txt          GRU Unit 29155 advisory
    attck_techniques_<tactic>.txt   One file per ATT&CK tactic
    attck_mitigations.txt       All ATT&CK mitigations
    nist_<FAMILY>.txt           One file per NIST control family
    nist_attck_crossref.txt     NIST ↔ ATT&CK bridge mappings
"""

import json
import os
from collections import defaultdict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "kb_output"
OUT_DIR.mkdir(exist_ok=True)


# HELPERS

def write_file(filename: str, lines: list[str]) -> None:
    content = "\n".join(lines)
    path    = OUT_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    words = len(content.split())
    print(f"  ✅  {filename:<50}  {words:>5} words")


def load(filename: str) -> list | dict:
    try:
        with open(BASE_DIR / filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"  ❌  {filename} not found — run download_attack.py first")
        return []


# 1.  CISA ADVISORIES  — one file per advisory
#     Keeping each advisory in its own file ensures the model can say
#     "according to AA23-061A" and be traced back to a specific document.

def prepare_cisa() -> int:
    chunks = load("parsed_cisa.json")
    if not chunks:
        return 0

    by_advisory: dict[str, list] = defaultdict(list)
    for chunk in chunks:
        by_advisory[chunk["advisory_id"]].append(chunk)

    for advisory_id, adv_chunks in sorted(by_advisory.items()):
        first = adv_chunks[0]
        lines = [
            f"SOURCE: CISA Advisory {advisory_id}",
            f"THREAT ACTOR: {first.get('threat_actor', 'Unknown')}",
            f"DATE: {first.get('date', 'Unknown')}",
            f"ADVISORY ID: {advisory_id}",
            "=" * 70,
            "",
        ]

        for chunk in adv_chunks:
            tech_ids = chunk.get("technique_ids", [])
            tech_str = ", ".join(tech_ids) if tech_ids else "N/A"

            lines += [
                f"SECTION: {chunk['section']}",
                f"TITLE: {chunk['title']}",
                f"ATT&CK TECHNIQUE IDs: {tech_str}",
                "",
                chunk["content"],
                "",
                "─" * 50,
                "",
            ]

        write_file(f"cisa_{advisory_id}.txt", lines)

    return len(by_advisory)


# 2.  ATT&CK TECHNIQUES  — one file per tactic
#     Grouping by tactic keeps each file semantically coherent and
#     within Open WebUI's default chunk size limits.  A single flat
#     file of 820+ techniques would produce poor chunk boundaries.

def prepare_techniques() -> int:
    techniques = load("parsed_techniques.json")
    if not techniques:
        return 0

    by_tactic: dict[str, list] = defaultdict(list)
    for t in techniques:
        tactic_str = t.get("tactics", "")
        # A technique may map to multiple tactics — use the first one
        # for file grouping to avoid duplicating entries
        primary_tactic = tactic_str.split(", ")[0].strip() if tactic_str else "Other"
        by_tactic[primary_tactic].append(t)

    for tactic, techs in sorted(by_tactic.items()):
        lines = [
            f"SOURCE: MITRE ATT&CK Enterprise — Tactic: {tactic}",
            f"FRAMEWORK: MITRE ATT&CK",
            f"TACTIC: {tactic}",
            f"TECHNIQUE COUNT: {len(techs)}",
            "=" * 70,
            "",
        ]

        for t in techs:
            # Truncate description/detection to keep file size reasonable
            # Open WebUI chunks at ~1500 chars by default; these fields
            # can be several thousand chars in the raw STIX data.
            desc    = (t.get("description") or "")[:700]
            detect  = (t.get("detection")   or "")[:400]

            lines += [
                f"TECHNIQUE: {t['name']}",
                f"TECHNIQUE ID: {t['technique_id']}",
                f"TACTIC: {t['tactics']}",
                f"PLATFORMS: {t['platforms']}",
                f"SUB-TECHNIQUE: {'Yes' if t.get('is_subtechnique') else 'No'}",
            ]
            if desc:
                lines.append(f"DESCRIPTION: {desc}")
            if detect:
                lines.append(f"DETECTION: {detect}")
            lines += ["", "─" * 50, ""]

        slug = tactic.lower().replace(" ", "-").replace("/", "-")
        write_file(f"attck_techniques_{slug}.txt", lines)

    return len(techniques)


# 3.  ATT&CK MITIGATIONS  — single file
#     ~100 mitigations fit comfortably in one file.  Keeping them together means a query for "mitigate credential dumping" lands
#     in a file where multiple related mitigations can be retrieved.

def prepare_mitigations() -> int:
    mitigations = load("parsed_mitigations.json")
    if not mitigations:
        return 0

    lines = [
        "SOURCE: MITRE ATT&CK Mitigations",
        "FRAMEWORK: MITRE ATT&CK",
        "=" * 70,
        "",
    ]

    for m in sorted(mitigations, key=lambda x: x["mitigation_id"]):
        desc = (m.get("description") or "")[:500]
        lines += [
            f"MITIGATION: {m['name']}",
            f"MITIGATION ID: {m['mitigation_id']}",
            f"ADDRESSES TECHNIQUES: {m['technique_ids']}",
        ]
        if desc:
            lines.append(f"DESCRIPTION: {desc}")
        lines += ["", "─" * 50, ""]

    write_file("attck_mitigations.txt", lines)
    return len(mitigations)

# 4.  NIST 800-53  — one file per control family
#     20 families, ~10-15 controls each — a natural grouping that
#     also matches how practitioners look up controls (e.g. "IR family"
#     or "AC family") rather than individual control IDs.

def prepare_nist() -> int:
    controls = load("parsed_nist_800_53.json")
    if not controls:
        return 0

    by_family: dict[str, list] = defaultdict(list)
    for c in controls:
        by_family[c["family_id"]].append(c)

    for family_id, family_controls in sorted(by_family.items()):
        family_title = family_controls[0]["family_title"]
        lines = [
            f"SOURCE: NIST SP 800-53 rev5 — Control Family {family_id}",
            f"FRAMEWORK: NIST SP 800-53 rev5",
            f"CONTROL FAMILY: {family_id} — {family_title}",
            f"CONTROL COUNT: {len(family_controls)}",
            "=" * 70,
            "",
        ]

        for c in family_controls:
            desc = (c.get("description") or "")[:600]
            enh  = (c.get("enhancements") or "")[:400]

            lines += [
                f"CONTROL: {c['control_id']} — {c['title']}",
                f"FAMILY: {family_id} ({family_title})",
                f"FRAMEWORK: NIST SP 800-53 rev5",
            ]
            if desc:
                lines.append(f"DESCRIPTION: {desc}")
            if enh:
                lines.append(f"ENHANCEMENTS: {enh}")
            lines += ["", "─" * 50, ""]

        write_file(f"nist_{family_id}.txt", lines)

    return len(controls)


# 5.  NIST ↔ ATT&CK CROSS-REFERENCE  — single file
#     This is the bridge file.  It's small (16 records) and the rationale
#     field is written as prose that embeds well for queries like
#     "what NIST control addresses T1486 ransomware".

def prepare_crossref() -> int:
    records = load("parsed_nist_attck_crossref.json")
    if not records:
        return 0

    lines = [
        "SOURCE: NIST SP 800-53 ↔ MITRE ATT&CK Cross-Reference Mapping",
        "FRAMEWORK: NIST SP 800-53 rev5 + MITRE ATT&CK Enterprise",
        (
            "PURPOSE: Maps NIST 800-53 defensive controls to ATT&CK mitigations "
            "and the specific techniques they address.  Use this to answer: "
            "'which NIST control mitigates technique T____?' or "
            "'which ATT&CK mitigation corresponds to control AC-6?'"
        ),
        "=" * 70,
        "",
    ]

    for r in records:
        nist    = ", ".join(r.get("nist_controls", []))
        mits    = ", ".join(r.get("attck_mitigations", [])) or "N/A"
        techs   = ", ".join(r.get("technique_ids", []))

        lines += [
            f"MAPPING ID: {r['mapping_id']}",
            f"CATEGORY: {r['category']}",
            f"NIST 800-53 CONTROLS: {nist}",
            f"ATT&CK MITIGATIONS: {mits}",
            f"ADDRESSED TECHNIQUES: {techs}",
            f"RATIONALE: {r['rationale']}",
            "",
            "─" * 50,
            "",
        ]

    write_file("nist_attck_crossref.txt", lines)
    return len(records)

# MAIN

def main():
    print("\n" + "═" * 70)
    print("  prepare_for_openwebui.py — Knowledge Base text file generator")
    print("═" * 70 + "\n")

    print("[1/5]  CISA Advisories")
    n_advisories = prepare_cisa()

    print("\n[2/5]  ATT&CK Techniques (grouped by tactic)")
    n_techniques = prepare_techniques()

    print("\n[3/5]  ATT&CK Mitigations")
    n_mitigations = prepare_mitigations()

    print("\n[4/5]  NIST 800-53 Controls (grouped by family)")
    n_controls = prepare_nist()

    print("\n[5/5]  NIST ↔ ATT&CK Cross-Reference")
    n_crossref = prepare_crossref()

    # ── Summary ───────────────────────────────────────────────────────────────
    files       = sorted(OUT_DIR.glob("*.txt"))
    total_bytes = sum(f.stat().st_size for f in files)

    print("\n" + "═" * 70)
    print(f"  {len(files)} files written to ./{OUT_DIR}/")
    print(f"  Total size : {total_bytes / 1024:.0f} KB")
    print(f"  Source records embedded:")
    print(f"    CISA advisories      : {n_advisories} advisories")
    print(f"    ATT&CK techniques    : {n_techniques}")
    print(f"    ATT&CK mitigations   : {n_mitigations}")
    print(f"    NIST 800-53 controls : {n_controls}")
    print(f"    NIST↔ATT&CK xref     : {n_crossref} mappings")
    print("═" * 70)

if __name__ == "__main__":
    main()
