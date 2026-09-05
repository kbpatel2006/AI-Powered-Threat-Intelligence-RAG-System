import requests
import json
import os
from pathlib import Path

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_FILE = BASE_DIR / "enterprise-attack.json"


def download_attack_data():
    if os.path.exists(OUTPUT_FILE):
        print(f"{OUTPUT_FILE} already exists so skipping download.")
        return

    print("Downloading MITRE ATT&CK Enterprise STIX bundle")
    r = requests.get(STIX_URL, stream=True)
    r.raise_for_status()

    with open(OUTPUT_FILE, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)

    print(f"Download complete: {OUTPUT_FILE}")


def parse_techniques(filepath):
    print("Parsing ATT&CK techniques from STIX bundle")

    with open(filepath, "r") as f:
        bundle = json.load(f)

    techniques = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        if obj.get("x_mitre_deprecated", False):
            continue

        tech_id = next(
            (
                ref["external_id"]
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack"
            ),
            None,
        )

        if not tech_id:
            continue

        tactics = [
            p["phase_name"].replace("-", " ").title()
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append(
            {
                "technique_id": tech_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactics": ", ".join(tactics),
                "platforms": ", ".join(obj.get("x_mitre_platforms", [])),
                "detection": obj.get("x_mitre_detection", ""),
            }
        )

    print(f"Parsed {len(techniques)} ATT&CK techniques")
    return techniques


if __name__ == "__main__":
    download_attack_data()
    techniques = parse_techniques(OUTPUT_FILE)

    # Save parsed data for inspection
    with open(BASE_DIR / "parsed_techniques.json", "w") as f:
        json.dump(techniques, f, indent=2)
    print("Saved parsed_techniques.json")

    # Preview the first technique
    print("\nPreview of first technique:")
    t = techniques[0]
    print(f"  ID:      {t['technique_id']}")
    print(f"  Name:    {t['name']}")
    print(f"  Tactics: {t['tactics']}")
    print(f"  Desc:    {t['description'][:200]}...")
