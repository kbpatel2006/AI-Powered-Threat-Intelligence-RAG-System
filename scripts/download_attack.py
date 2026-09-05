"""

Pulls and parses five data sources into cleaner JSON files ready for ingestion into ChromaDB:

  1. parsed_techniques.json        — MITRE ATT&CK technique definitions
  2. parsed_mitigations.json       — ATT&CK mitigations mapped to techniques
  3. parsed_cisa.json              — CISA advisory chunks (4 advisories)
  4. parsed_nist_800_53.json       — NIST 800-53 rev5 control summaries
  5. parsed_nist_attck_crossref.json — NIST control ↔ ATT&CK technique/mitigation bridge

"""

import json
import os
import re
import requests
from pathlib import Path
from tqdm import tqdm


# SOURCE URLs

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
BASE_DIR = Path(__file__).resolve().parent
STIX_LOCAL = BASE_DIR / "enterprise-attack.json"

NIST_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
NIST_LOCAL = BASE_DIR / "NIST_SP-800-53_rev5_catalog.json"

# OUTPUT FILES

OUT_TECHNIQUES  = BASE_DIR / "parsed_techniques.json"
OUT_MITIGATIONS = BASE_DIR / "parsed_mitigations.json"
OUT_CISA        = BASE_DIR / "parsed_cisa.json"
OUT_NIST        = BASE_DIR / "parsed_nist_800_53.json"
OUT_CROSSREF    = BASE_DIR / "parsed_nist_attck_crossref.json"

# HELPERS

def _clean(text: str) -> str:
    """Cleans the page"""
    text = re.sub(r"\(Citation:[^)]+\)", "", text or "")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _download(url: str, local_path: str, label: str) -> dict | list:
    """Download a JSON file if not already cached locally."""
    if os.path.exists(local_path):
        print(f"Using cached {local_path}")
    else:
        print(f"Downloading {label} …")
        r = requests.get(url, timeout=120)
        r.raise_for_status()
        with open(local_path, "wb") as f:
            f.write(r.content)
        print(f"Saved to {local_path}")

    with open(local_path, "r", encoding="utf-8") as f:
        return json.load(f)


# 1.  ATT&CK TECHNIQUES

def parse_techniques(bundle: dict) -> list[dict]:
    """Extract active attack-pattern objects from the STIX bundle."""
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        tech_id  = next(
            (r["external_id"] for r in ext_refs
             if r.get("source_name") == "mitre-attack"), None
        )
        if not tech_id:
            continue

        tactics = [
            p["phase_name"].replace("-", " ").title()
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append({
            "technique_id":    tech_id,
            "name":            obj.get("name", ""),
            "description":     _clean(obj.get("description", "")),
            "tactics":         ", ".join(tactics),
            "platforms":       ", ".join(obj.get("x_mitre_platforms", [])),
            "detection":       _clean(obj.get("x_mitre_detection", "")),
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            "stix_id":         obj.get("id", ""),
        })

    print(f"Parsed {len(techniques)} ATT&CK techniques")
    return techniques


# 2.  ATT&CK MITIGATIONS  (course-of-action objects + relationships)

def parse_mitigations(bundle: dict) -> list[dict]:
    """
    Extract ATT&CK mitigations and map each one to the technique(s)
    it addresses via STIX 'mitigates' relationships.
    """
    objects = bundle.get("objects", [])

    # stix_id → ATT&CK technique ID
    stix_to_tech: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            ext = obj.get("external_references", [])
            tid = next(
                (r["external_id"] for r in ext
                 if r.get("source_name") == "mitre-attack"), None
            )
            if tid:
                stix_to_tech[obj["id"]] = tid

    # stix_id → mitigation record
    mit_by_id: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") == "course-of-action" and not obj.get("revoked"):
            ext    = obj.get("external_references", [])
            mit_id = next(
                (r["external_id"] for r in ext
                 if r.get("source_name") == "mitre-attack"), None
            )
            if mit_id:
                mit_by_id[obj["id"]] = {
                    "mitigation_id": mit_id,
                    "name":          obj.get("name", ""),
                    "description":   _clean(obj.get("description", "")),
                    "stix_id":       obj["id"],
                    "technique_ids": [],
                }

    # Walk 'mitigates' relationships
    for obj in objects:
        if (obj.get("type") == "relationship"
                and obj.get("relationship_type") == "mitigates"):
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            if src in mit_by_id and tgt in stix_to_tech:
                mit_by_id[src]["technique_ids"].append(stix_to_tech[tgt])

    mitigations = list(mit_by_id.values())
    for m in mitigations:
        m["technique_ids"] = ", ".join(sorted(set(m["technique_ids"])))

    print(f"Parsed {len(mitigations)} ATT&CK mitigations")
    return mitigations


# 3.  CISA ADVISORIES
#     Four advisories covering distinct threat actor categories:
#       AA23-144A  Volt Typhoon     (PRC / LotL / critical infrastructure)
#       AA24-038A  PRC KV Botnet    (PRC / SOHO / OT pre-positioning)
#       AA23-061A  Royal Ransomware (ransomware / extortion)
#       AA23-320A  Scattered Spider (social engineering / cloud / SIM swap)
#       AA24-190A  GRU Unit 29155   (Russia / destructive / NATO targeting)
#
#     Each chunk now includes a structured `technique_ids` list so the RAG system can join on technique IDs without parsing prose text.

CISA_CHUNKS: list[dict] = [

    # AA23-144A  —  Volt Typhoon (PRC, Living Off The Land)
    {
        "advisory_id":   "AA23-144A",
        "title":         "Volt Typhoon — Overview",
        "date":          "2023-05-24",
        "section":       "Overview",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": [],
        "content": (
            "Volt Typhoon is a People's Republic of China (PRC) state-sponsored "
            "cyber actor active since at least mid-2021. The actor targets U.S. "
            "critical infrastructure including communications, energy, transportation, "
            "and water sectors. CISA, NSA, and FBI assess Volt Typhoon is "
            "pre-positioning on IT networks to enable lateral movement to OT assets "
            "to disrupt critical functions during geopolitical tensions or military "
            "conflict with the United States."
        ),
    },
    {
        "advisory_id":   "AA23-144A",
        "title":         "Volt Typhoon — Living Off The Land Techniques",
        "date":          "2023-05-24",
        "section":       "TTPs — Living Off The Land",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": ["T1059", "T1059.001", "T1047"],
        "content": (
            "Volt Typhoon relies almost exclusively on living-off-the-land (LotL) "
            "techniques and built-in Windows tools including wmic (T1047), ntdsutil, "
            "netsh, and PowerShell (T1059.001) to blend in with normal system "
            "activity. The actor minimizes custom malware use to avoid detection, "
            "using command-line interfaces to execute commands and scripts (T1059) "
            "and Windows Management Instrumentation for execution and discovery (T1047)."
        ),
    },
    {
        "advisory_id":   "AA23-144A",
        "title":         "Volt Typhoon — Initial Access",
        "date":          "2023-05-24",
        "section":       "TTPs — Initial Access",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": ["T1190", "T1078"],
        "content": (
            "Volt Typhoon gains initial access primarily by exploiting internet-facing "
            "network appliances: Fortinet FortiGuard, Ivanti Connect Secure, NETGEAR, "
            "Citrix, and Cisco RV320/325 routers. Techniques used include exploitation "
            "of public-facing applications (T1190) and use of valid accounts (T1078) "
            "obtained through credential access. The actor targets VPN infrastructure "
            "to establish footholds in victim networks."
        ),
    },
    {
        "advisory_id":   "AA23-144A",
        "title":         "Volt Typhoon — Credential Access",
        "date":          "2023-05-24",
        "section":       "TTPs — Credential Access",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": ["T1003.001", "T1555.003", "T1078"],
        "content": (
            "Volt Typhoon performs credential dumping using ntdsutil.exe for Active "
            "Directory credential extraction and comsvcs.dll to dump LSASS memory "
            "(T1003.001). The group also extracts credentials from web browsers "
            "(T1555.003) and leverages harvested credentials via valid accounts "
            "(T1078) to access additional systems without deploying further tooling."
        ),
    },
    {
        "advisory_id":   "AA23-144A",
        "title":         "Volt Typhoon — Command and Control",
        "date":          "2023-05-24",
        "section":       "TTPs — C2",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": ["T1090.002", "T1572"],
        "content": (
            "Volt Typhoon routes C2 traffic through compromised SOHO network devices "
            "including NETGEAR, Cisco, and ASUS routers (T1090.002 — External Proxy). "
            "This blends malicious traffic with legitimate network activity and "
            "obscures the true source of intrusions. The group also uses the "
            "open-source FRP (Fast Reverse Proxy) tool to establish encrypted tunnels "
            "for C2 communication (T1572 — Protocol Tunneling)."
        ),
    },
    {
        "advisory_id":   "AA23-144A",
        "title":         "Volt Typhoon — Defense Evasion",
        "date":          "2023-05-24",
        "section":       "TTPs — Defense Evasion",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": ["T1070.004", "T1036", "T1090"],
        "content": (
            "Volt Typhoon deletes command history and log files (T1070.004 — "
            "Indicator Removal on Host: File Deletion) and masquerades malicious "
            "processes as legitimate system processes (T1036). The actor uses proxy "
            "infrastructure through compromised devices to obfuscate network traffic "
            "(T1090) and deliberately maintains a low operational tempo — a 'low and "
            "slow' approach — to avoid triggering behavioral detection systems."
        ),
    },
    {
        "advisory_id":   "AA23-144A",
        "title":         "Volt Typhoon — Discovery",
        "date":          "2023-05-24",
        "section":       "TTPs — Discovery",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": ["T1049", "T1016", "T1082", "T1046"],
        "content": (
            "Volt Typhoon conducts network and system discovery using built-in "
            "Windows tools: netstat for active network connections (T1049), ipconfig "
            "and net commands for network configuration (T1016), PowerShell "
            "Get-NetTCPConnection, and wmic and system utilities for process/system "
            "enumeration (T1082). The actor maps victim network topology before "
            "lateral movement and uses port scanning for network service discovery "
            "(T1046)."
        ),
    },
    {
        "advisory_id":   "AA23-144A",
        "title":         "Volt Typhoon — Mitigations",
        "date":          "2023-05-24",
        "section":       "Mitigations",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": ["T1190", "T1078", "T1003.001", "T1090.002"],
        "content": (
            "CISA recommended mitigations against Volt Typhoon: (1) Apply patches for "
            "internet-facing systems immediately, prioritizing network appliances and "
            "VPN. (2) Enforce multi-factor authentication on all remote access. "
            "(3) Audit and remove unnecessary accounts; enforce least privilege. "
            "(4) Monitor for unusual use of wmic, ntdsutil, netsh, and PowerShell "
            "outside maintenance windows. (5) Implement network segmentation between "
            "IT and OT. (6) Enable enhanced logging including PowerShell script block "
            "logging and Windows event logs. (7) Review and restrict outbound "
            "connections to SOHO device IP ranges."
        ),
    },
    {
        "advisory_id":   "AA23-144A",
        "title":         "Volt Typhoon — Affected Sectors",
        "date":          "2023-05-24",
        "section":       "Affected Sectors",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": [],
        "content": (
            "Volt Typhoon has been confirmed targeting U.S. critical infrastructure: "
            "Communications, Energy (including electric utilities), Transportation "
            "Systems (maritime and aviation), Water and Wastewater Systems, and "
            "government facilities. The combination of LotL techniques and "
            "pre-positioning behavior indicates preparation for potential disruptive "
            "or destructive cyberattacks rather than traditional espionage."
        ),
    },

    # AA24-038A  —  PRC KV Botnet / SOHO Compromise (Feb 2024 follow-up)
    {
        "advisory_id":   "AA24-038A",
        "title":         "PRC Actors — KV Botnet via SOHO Routers",
        "date":          "2024-02-07",
        "section":       "Key Finding — KV Botnet",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": ["T1090.002", "T1584.005"],
        "content": (
            "A February 2024 joint CISA/NSA/FBI advisory confirmed that PRC "
            "state-sponsored actors including Volt Typhoon operate a botnet of "
            "compromised SOHO routers known as the KV Botnet, used to proxy C2 "
            "traffic (T1090.002) and obfuscate intrusion origins. Affected devices "
            "include Cisco RV320/325, NETGEAR ProSAFE, and Axis IP cameras. "
            "Organizations should audit SOHO perimeter devices and isolate or "
            "replace end-of-life hardware immediately. The actors also compromise "
            "third-party infrastructure for use as operational relay boxes "
            "(T1584.005 — Compromise Infrastructure: Botnet)."
        ),
    },
    {
        "advisory_id":   "AA24-038A",
        "title":         "PRC Actors — OT Pre-Positioning Intent",
        "date":          "2024-02-07",
        "section":       "Key Finding — OT Intent",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": ["T1078", "T1021", "T1190"],
        "content": (
            "The 2024 advisory elevated the threat assessment, stating that PRC "
            "state-sponsored actors are pre-positioning on U.S. critical "
            "infrastructure IT networks specifically to enable disruptive or "
            "destructive cyberattacks against OT systems during a major crisis or "
            "conflict. Valid accounts (T1078) and remote services (T1021) are the "
            "primary persistence mechanisms observed. Electric, water, transportation, "
            "and communications sectors are priority targets. Organizations should "
            "assume Volt Typhoon may already have persistent access and conduct "
            "proactive threat hunting."
        ),
    },
    {
        "advisory_id":   "AA24-038A",
        "title":         "PRC Actors — Detection Recommendations",
        "date":          "2024-02-07",
        "section":       "Detection Recommendations",
        "threat_actor":  "Volt Typhoon (PRC)",
        "technique_ids": ["T1003.001", "T1059.001", "T1047", "T1090.002"],
        "content": (
            "AA24-038A specific detection guidance: Monitor ntdsutil.exe and "
            "comsvcs.dll execution outside maintenance windows (T1003.001 LSASS "
            "dump indicator). Alert on PowerShell encoded command execution and "
            "unusual wmic queries (T1059.001, T1047). Monitor authentication logs "
            "for accounts authenticating from unexpected source IPs — especially "
            "VPN/remote access. Implement LOLBin behavioral detection for certutil, "
            "mshta, and regsvr32 in unusual contexts. Deploy network flow monitoring "
            "to detect unusual outbound traffic to SOHO device IP ranges (T1090.002)."
        ),
    },

    # AA23-061A  —  Royal Ransomware (CISA + FBI, March 2023)
    {
        "advisory_id":   "AA23-061A",
        "title":         "Royal Ransomware — Overview",
        "date":          "2023-03-02",
        "section":       "Overview",
        "threat_actor":  "Royal Ransomware Group",
        "technique_ids": ["T1486", "T1489"],
        "content": (
            "Royal ransomware is a highly capable ransomware variant operated by a "
            "sophisticated threat group active since at least September 2022. CISA "
            "and the FBI issued AA23-061A noting Royal has targeted U.S. and "
            "international critical infrastructure including healthcare, education, "
            "manufacturing, and communications. Royal encrypts files (T1486 — Data "
            "Encrypted for Impact) and stops critical services before encryption "
            "(T1489 — Service Stop). The group demands ransoms ranging from "
            "$1 million to $11 million USD."
        ),
    },
    {
        "advisory_id":   "AA23-061A",
        "title":         "Royal Ransomware — Initial Access and Phishing",
        "date":          "2023-03-02",
        "section":       "TTPs — Initial Access",
        "threat_actor":  "Royal Ransomware Group",
        "technique_ids": ["T1566.001", "T1566.002", "T1078", "T1190"],
        "content": (
            "Royal primarily gains initial access via callback phishing — victims "
            "receive emails inducing them to call a phone number (T1566.001 "
            "Spearphishing Attachment variant). The caller is then socially "
            "engineered into installing remote access software. Additional vectors "
            "include malicious links (T1566.002), exploitation of public-facing "
            "applications (T1190), and use of valid credentials purchased from "
            "initial access brokers (T1078). Royal has also exploited unpatched "
            "vulnerabilities in Citrix and FortiOS."
        ),
    },
    {
        "advisory_id":   "AA23-061A",
        "title":         "Royal Ransomware — Execution and Persistence",
        "date":          "2023-03-02",
        "section":       "TTPs — Execution / Persistence",
        "threat_actor":  "Royal Ransomware Group",
        "technique_ids": ["T1059.003", "T1547.001", "T1053.005", "T1112"],
        "content": (
            "Royal uses Windows Command Shell (T1059.003) and PowerShell for "
            "execution. Persistence is established via registry run keys (T1547.001) "
            "and scheduled tasks (T1053.005). The group modifies the registry "
            "(T1112) to disable security tools and configure autostart. Royal has "
            "been observed deploying Cobalt Strike beacons and Qakbot/QBot malware "
            "as intermediate stages before deploying the final ransomware payload."
        ),
    },
    {
        "advisory_id":   "AA23-061A",
        "title":         "Royal Ransomware — Lateral Movement and Exfiltration",
        "date":          "2023-03-02",
        "section":       "TTPs — Lateral Movement / Exfiltration",
        "threat_actor":  "Royal Ransomware Group",
        "technique_ids": ["T1021.001", "T1021.002", "T1048", "T1485"],
        "content": (
            "Royal moves laterally using Remote Desktop Protocol (T1021.001) and "
            "SMB/Windows Admin Shares (T1021.002). Prior to encryption, the group "
            "exfiltrates data for double-extortion using tools such as Cobalt Strike "
            "and MEGAsync (T1048 — Exfiltration Over Alternative Protocol). Royal "
            "then deletes volume shadow copies (T1485 — Data Destruction) to prevent "
            "recovery and deploys the ransomware encryptor using batch scripts or "
            "PsExec for network-wide execution."
        ),
    },
    {
        "advisory_id":   "AA23-061A",
        "title":         "Royal Ransomware — Mitigations",
        "date":          "2023-03-02",
        "section":       "Mitigations",
        "threat_actor":  "Royal Ransomware Group",
        "technique_ids": ["T1486", "T1566", "T1078", "T1021.001"],
        "content": (
            "CISA/FBI recommended mitigations against Royal: (1) Maintain offline, "
            "encrypted backups tested regularly. (2) Implement a recovery plan for "
            "multiple backup copies in different locations. (3) Apply patches "
            "promptly, prioritizing internet-facing systems. (4) Enforce MFA on all "
            "accounts, especially RDP (T1021.001). (5) Segment networks to limit "
            "ransomware propagation. (6) Disable unnecessary remote access services. "
            "(7) Deploy endpoint detection and response (EDR) with behavioral "
            "analytics. (8) Train users to identify phishing attempts (T1566). "
            "(9) Monitor for volume shadow copy deletion commands."
        ),
    },

    # AA23-320A  —  Scattered Spider (CISA + FBI, November 2023)
    {
        "advisory_id":   "AA23-320A",
        "title":         "Scattered Spider — Overview",
        "date":          "2023-11-16",
        "section":       "Overview",
        "threat_actor":  "Scattered Spider (UNC3944)",
        "technique_ids": [],
        "content": (
            "Scattered Spider (also known as UNC3944, Muddled Libra, and 0ktapus) "
            "is a financially motivated threat actor active since at least 2022. "
            "CISA and FBI issued AA23-320A noting the group's sophisticated social "
            "engineering capabilities and focus on cloud environments. The group "
            "has targeted telecommunications, technology, hospitality, and financial "
            "services organizations. Scattered Spider members are English-speaking "
            "and often pose as help desk or IT support staff."
        ),
    },
    {
        "advisory_id":   "AA23-320A",
        "title":         "Scattered Spider — Social Engineering and Initial Access",
        "date":          "2023-11-16",
        "section":       "TTPs — Initial Access",
        "threat_actor":  "Scattered Spider (UNC3944)",
        "technique_ids": ["T1566.004", "T1621", "T1656", "T1078"],
        "content": (
            "Scattered Spider is known for sophisticated social engineering. TTPs "
            "include: SIM swapping to intercept SMS MFA codes (T1621 — MFA Request "
            "Generation); voice phishing (vishing) impersonating IT help desk staff "
            "to trick employees into revealing credentials; phishing kits including "
            "Okta credential harvesters (T1566.004); and impersonation of vendor "
            "support (T1656 — Impersonation). Once credentials are obtained, the "
            "group uses valid accounts (T1078) for initial access to cloud platforms "
            "and VPN systems."
        ),
    },
    {
        "advisory_id":   "AA23-320A",
        "title":         "Scattered Spider — Cloud and Identity Abuse",
        "date":          "2023-11-16",
        "section":       "TTPs — Cloud Exploitation",
        "threat_actor":  "Scattered Spider (UNC3944)",
        "technique_ids": ["T1530", "T1537", "T1556.006", "T1538"],
        "content": (
            "After gaining initial access, Scattered Spider targets cloud identity "
            "infrastructure heavily. TTPs include: accessing data from cloud storage "
            "(T1530 — Data from Cloud Storage Object); transferring data to external "
            "cloud accounts (T1537 — Transfer Data to Cloud Account); modifying "
            "cloud authentication processes including SSO and Okta (T1556.006); and "
            "enumerating cloud infrastructure via management APIs (T1538 — Cloud "
            "Service Dashboard). The group has been observed creating new Okta "
            "accounts and modifying identity provider configurations to establish "
            "persistent access."
        ),
    },
    {
        "advisory_id":   "AA23-320A",
        "title":         "Scattered Spider — Data Theft and Extortion",
        "date":          "2023-11-16",
        "section":       "TTPs — Exfiltration / Impact",
        "threat_actor":  "Scattered Spider (UNC3944)",
        "technique_ids": ["T1041", "T1567.002", "T1657"],
        "content": (
            "Scattered Spider's primary objective is data theft for extortion. The "
            "group exfiltrates data over existing C2 channels (T1041) and uses cloud "
            "services like MEGA for exfiltration (T1567.002 — Exfiltration to Code "
            "Repository). The group employs financial extortion (T1657 — Financial "
            "Theft) by threatening to release stolen data publicly. In later "
            "campaigns, the group deployed BlackCat/ALPHV ransomware in addition to "
            "data theft, indicating a shift toward combined ransomware and extortion "
            "attacks."
        ),
    },
    {
        "advisory_id":   "AA23-320A",
        "title":         "Scattered Spider — Mitigations",
        "date":          "2023-11-16",
        "section":       "Mitigations",
        "threat_actor":  "Scattered Spider (UNC3944)",
        "technique_ids": ["T1621", "T1566.004", "T1078", "T1530"],
        "content": (
            "CISA/FBI recommended mitigations against Scattered Spider: "
            "(1) Implement phishing-resistant MFA (FIDO2/hardware tokens) — "
            "SMS and voice-based MFA are susceptible to SIM swapping. "
            "(2) Establish strict identity verification procedures for help desk "
            "interactions including callback verification to known numbers. "
            "(3) Deploy conditional access policies based on device compliance and "
            "geographic location. (4) Monitor cloud logs for unusual account "
            "creation, role assignments, and SSO configuration changes. "
            "(5) Conduct user awareness training on vishing and social engineering. "
            "(6) Implement data loss prevention (DLP) controls on cloud storage. "
            "(7) Review and audit identity provider (IdP) configurations regularly."
        ),
    },

    # AA24-190A  —  GRU Unit 29155 (CISA/NSA/FBI/NCSC, July 2024)
    {
        "advisory_id":   "AA24-190A",
        "title":         "GRU Unit 29155 — Overview",
        "date":          "2024-07-09",
        "section":       "Overview",
        "threat_actor":  "GRU Unit 29155 (Russia)",
        "technique_ids": [],
        "content": (
            "GRU Unit 29155, also known as Cadet Blizzard and previously associated "
            "with WhisperGate destructive malware, is a Russian military intelligence "
            "(GRU) unit responsible for global operations including cyberattacks, "
            "assassinations, and sabotage. A July 2024 joint advisory (AA24-190A) "
            "from CISA, NSA, FBI, and international partners identified Unit 29155 "
            "as conducting espionage and disruptive cyberattacks against NATO member "
            "states, Ukraine, and other European governments since at least 2020. "
            "The unit operates with disruptive and destructive objectives distinct "
            "from traditional Russian intelligence cyber units."
        ),
    },
    {
        "advisory_id":   "AA24-190A",
        "title":         "GRU Unit 29155 — Initial Access and Reconnaissance",
        "date":          "2024-07-09",
        "section":       "TTPs — Initial Access",
        "threat_actor":  "GRU Unit 29155 (Russia)",
        "technique_ids": ["T1595", "T1190", "T1133", "T1589"],
        "content": (
            "GRU Unit 29155 conducts extensive pre-compromise reconnaissance "
            "(T1595 — Active Scanning) including subdomain enumeration and "
            "vulnerability scanning of target infrastructure. Initial access is "
            "primarily achieved through exploitation of public-facing applications "
            "(T1190) including CVE-2021-33044 (Dahua IP cameras), CVE-2022-26134 "
            "(Atlassian Confluence), and various edge device CVEs. The unit also "
            "uses external remote services (T1133) and conducts credential gathering "
            "operations (T1589 — Gather Victim Identity Information) to identify "
            "valid accounts for initial access."
        ),
    },
    {
        "advisory_id":   "AA24-190A",
        "title":         "GRU Unit 29155 — Destructive Malware and WhisperGate",
        "date":          "2024-07-09",
        "section":       "TTPs — Destructive Activity",
        "threat_actor":  "GRU Unit 29155 (Russia)",
        "technique_ids": ["T1561.002", "T1485", "T1491.001"],
        "content": (
            "GRU Unit 29155's most notable destructive capability is WhisperGate, "
            "a multi-stage wiper malware that corrupts the Master Boot Record "
            "(T1561.002 — Disk Structure Wipe) and overwrites files to render "
            "systems unbootable. The unit also conducts data destruction operations "
            "(T1485 — Data Destruction) and website defacement (T1491.001 — "
            "Defacement: Internal Defacement). These destructive objectives "
            "distinguish Unit 29155 from espionage-focused Russian APT groups. "
            "The advisory notes deployments of WhisperGate against Ukrainian "
            "government and critical infrastructure targets in January 2022."
        ),
    },
    {
        "advisory_id":   "AA24-190A",
        "title":         "GRU Unit 29155 — Persistence and Lateral Movement",
        "date":          "2024-07-09",
        "section":       "TTPs — Persistence / Lateral Movement",
        "threat_actor":  "GRU Unit 29155 (Russia)",
        "technique_ids": ["T1505.003", "T1021.002", "T1550.002", "T1078"],
        "content": (
            "Unit 29155 establishes persistence using web shells (T1505.003 — "
            "Server Software Component: Web Shell) on compromised internet-facing "
            "servers. Lateral movement is conducted via SMB/Windows Admin Shares "
            "(T1021.002) and pass-the-hash techniques (T1550.002). The unit uses "
            "valid accounts (T1078) extensively once inside the network. Tools "
            "observed include Impacket for lateral movement, and the group leverages "
            "Active Directory enumeration to identify high-value targets before "
            "deploying destructive payloads."
        ),
    },
    {
        "advisory_id":   "AA24-190A",
        "title":         "GRU Unit 29155 — Mitigations",
        "date":          "2024-07-09",
        "section":       "Mitigations",
        "threat_actor":  "GRU Unit 29155 (Russia)",
        "technique_ids": ["T1190", "T1561.002", "T1505.003", "T1078"],
        "content": (
            "CISA/NSA recommended mitigations against GRU Unit 29155: "
            "(1) Prioritize patching internet-facing systems — especially edge "
            "devices, VPN, and collaboration tools exploited by this unit. "
            "(2) Implement immutable, offline backups to recover from wiper attacks. "
            "(3) Harden web-facing servers to prevent web shell deployment; monitor "
            "for unusual web server process children. (4) Deploy network monitoring "
            "for unusual SMB activity and lateral movement indicators. "
            "(5) Enforce least privilege and segment networks to limit blast radius "
            "of destructive payload deployment. (6) Enable Windows Defender "
            "Credential Guard to prevent pass-the-hash. (7) Monitor for MBR "
            "modification and mass file overwrite activity as destructive indicators."
        ),
    },
]


def build_cisa_records() -> list[dict]:
    """Return the structured CISA advisory chunks ready for embedding."""
    advisory_ids = {c["advisory_id"] for c in CISA_CHUNKS}
    print(
        f"Prepared {len(CISA_CHUNKS)} CISA advisory chunks "
        f"across {len(advisory_ids)} advisories: "
        f"{', '.join(sorted(advisory_ids))}"
    )
    return CISA_CHUNKS


# 4.  NIST 800-53 rev5 CONTROLS

def download_nist(url: str, local_path: str) -> dict:
    return _download(url, local_path, "NIST SP 800-53 rev5 OSCAL catalog")


def parse_nist_controls(catalog: dict) -> list[dict]:
    """
    Parse NIST 800-53 rev5 OSCAL catalog into flat control records.
    Flattens group → control → enhancement hierarchy.
    """
    controls = []

    def _extract_prose(parts: list) -> str:
        texts = []
        for part in (parts or []):
            if part.get("prose"):
                texts.append(_clean(part["prose"]))
            if part.get("parts"):
                texts.append(_extract_prose(part["parts"]))
        return " ".join(filter(None, texts))

    for group in catalog.get("catalog", {}).get("groups", []):
        family_id    = group.get("id", "").upper()
        family_title = group.get("title", "")

        for ctrl in group.get("controls", []):
            ctrl_id    = ctrl.get("id", "").upper().replace("_", "-")
            ctrl_title = ctrl.get("title", "")
            prose      = _extract_prose(ctrl.get("parts", []))

            enhancements = []
            for enh in ctrl.get("controls", []):
                enh_id    = enh.get("id", "").upper().replace("_", "-")
                enh_title = enh.get("title", "")
                enh_prose = _extract_prose(enh.get("parts", []))
                enhancements.append(f"{enh_id}: {enh_title} — {enh_prose}")

            controls.append({
                "control_id":   ctrl_id,
                "title":        ctrl_title,
                "family_id":    family_id,
                "family_title": family_title,
                "description":  prose,
                "enhancements": " | ".join(enhancements),
                "framework":    "NIST SP 800-53 rev5",
            })

    print(f"Parsed {len(controls)} NIST 800-53 controls")
    return controls


# 5.  NIST 800-53 - ATT&CK CROSS-REFERENCE 
#     This mapping bridges the gap between NIST defensive controls and
#     ATT&CK offensive techniques/mitigations.  Each record answers:
#
#       "Which NIST control(s) address this ATT&CK technique, and which
#        ATT&CK mitigation(s) does the control correspond to?"
#
#     Sourced from:
#       - NIST SP 800-53 rev5 Appendix H (mapping to ATT&CK)
#       - MITRE ATT&CK Navigator NIST 800-53 layer
#       - CISA CPG (Cross-Sector Cybersecurity Performance Goals) mapping
#
#     Format:
#       nist_controls    : list of NIST control IDs (e.g. ["AC-2", "AC-6"])
#       attck_mitigations: list of ATT&CK mitigation IDs (e.g. ["M1026"])
#       technique_ids    : list of ATT&CK technique IDs addressed
#       category         : human-readable security domain
#       rationale        : why these map together

NIST_ATTCK_CROSSREF: list[dict] = [

    # ── Identity & Access Management ──────────────────────────────────────────
    {
        "mapping_id":        "XREF-001",
        "category":          "Identity and Access Management",
        "nist_controls":     ["AC-2", "AC-3", "AC-6"],
        "attck_mitigations": ["M1026", "M1018"],
        "technique_ids":     ["T1078", "T1136", "T1548", "T1134"],
        "rationale": (
            "AC-2 (Account Management) and AC-6 (Least Privilege) directly "
            "correspond to ATT&CK Mitigation M1026 (Privileged Account Management). "
            "These controls limit the blast radius of T1078 (Valid Accounts) abuse "
            "and prevent T1548 (Abuse Elevation Control Mechanism). AC-3 (Access "
            "Enforcement) maps to M1018 (User Account Management) to constrain "
            "unauthorized account creation (T1136)."
        ),
    },
    {
        "mapping_id":        "XREF-002",
        "category":          "Multi-Factor Authentication",
        "nist_controls":     ["IA-2", "IA-5", "IA-12"],
        "attck_mitigations": ["M1032", "M1027"],
        "technique_ids":     ["T1078", "T1110", "T1621", "T1556"],
        "rationale": (
            "IA-2 (Identification and Authentication) maps to M1032 (Multi-Factor "
            "Authentication), the primary control against credential-based attacks "
            "T1078 (Valid Accounts) and T1110 (Brute Force). IA-5 (Authenticator "
            "Management) corresponds to M1027 (Password Policies) to mitigate "
            "T1110 and credential theft. IA-12 directly supports resistance to "
            "T1621 (MFA Request Generation) used by Scattered Spider."
        ),
    },
    {
        "mapping_id":        "XREF-003",
        "category":          "Credential Protection",
        "nist_controls":     ["SC-28", "SC-28(1)", "IA-5"],
        "attck_mitigations": ["M1041", "M1027", "M1026"],
        "technique_ids":     ["T1003", "T1003.001", "T1555", "T1552"],
        "rationale": (
            "SC-28 (Protection of Information at Rest) with enhancement SC-28(1) "
            "(Cryptographic Protection) maps to M1041 (Encrypt Sensitive Information) "
            "to protect credentials stored on disk from T1003 (OS Credential "
            "Dumping) and T1555 (Credentials from Password Stores). IA-5 supplemented "
            "by M1027 constrains exposure of cleartext credentials (T1552)."
        ),
    },
    {
        "mapping_id":        "XREF-004",
        "category":          "Remote Access Control",
        "nist_controls":     ["AC-17", "AC-17(1)", "SC-8"],
        "attck_mitigations": ["M1035", "M1037"],
        "technique_ids":     ["T1133", "T1021", "T1021.001", "T1090"],
        "rationale": (
            "AC-17 (Remote Access) and its encryption enhancement AC-17(1) map to "
            "M1035 (Limit Access to Resource over Network) to restrict T1133 "
            "(External Remote Services) and T1021 (Remote Services) abuse. SC-8 "
            "(Transmission Confidentiality) corresponds to M1037 (Filter Network "
            "Traffic) to detect and block unauthorized proxy tunnels (T1090) and "
            "RDP lateral movement (T1021.001)."
        ),
    },

    # ── Logging, Monitoring, and Detection ────────────────────────────────────
    {
        "mapping_id":        "XREF-005",
        "category":          "Audit Logging and Monitoring",
        "nist_controls":     ["AU-2", "AU-3", "AU-6", "AU-12"],
        "attck_mitigations": ["M1047"],
        "technique_ids":     ["T1562.001", "T1562.002", "T1070", "T1070.004"],
        "rationale": (
            "AU-2 (Event Logging), AU-3 (Content of Audit Records), AU-6 (Audit "
            "Record Review), and AU-12 (Audit Record Generation) collectively map "
            "to M1047 (Audit) and provide the detection foundation against T1562 "
            "(Impair Defenses) and T1070 (Indicator Removal on Host). Comprehensive "
            "logging is the primary detection mechanism for T1070.004 (File "
            "Deletion) used by Volt Typhoon to remove command history."
        ),
    },
    {
        "mapping_id":        "XREF-006",
        "category":          "Security Monitoring and Anomaly Detection",
        "nist_controls":     ["SI-4", "SI-4(2)", "SI-4(4)"],
        "attck_mitigations": ["M1031", "M1035"],
        "technique_ids":     ["T1046", "T1049", "T1016", "T1018", "T1595"],
        "rationale": (
            "SI-4 (System Monitoring) and its network monitoring enhancements "
            "SI-4(2) (Automated Tools for Real-Time Analysis) and SI-4(4) "
            "(Inbound and Outbound Communications Traffic) map to M1031 (Network "
            "Intrusion Prevention). These controls detect discovery activity "
            "including T1046 (Network Service Discovery), T1049 (System Network "
            "Connections Discovery), T1016 (System Network Configuration Discovery), "
            "and T1595 (Active Scanning) used in pre-attack reconnaissance."
        ),
    },

    # Patch Management and Vulnerability Remediation
    {
        "mapping_id":        "XREF-007",
        "category":          "Patch and Vulnerability Management",
        "nist_controls":     ["SI-2", "SI-2(2)", "RA-5"],
        "attck_mitigations": ["M1051", "M1019"],
        "technique_ids":     ["T1190", "T1203", "T1211", "T1068"],
        "rationale": (
            "SI-2 (Flaw Remediation) and SI-2(2) (Automated Flaw Remediation Status) "
            "directly map to M1051 (Update Software) — the primary control against "
            "T1190 (Exploit Public-Facing Application) used by Volt Typhoon and "
            "GRU Unit 29155, and T1203 (Exploitation for Client Execution). RA-5 "
            "(Vulnerability Monitoring and Scanning) supports M1019 (Threat "
            "Intelligence Program) to maintain awareness of exploitable vulnerabilities."
        ),
    },

    # Configuration Management
    {
        "mapping_id":        "XREF-008",
        "category":          "Secure Configuration Management",
        "nist_controls":     ["CM-2", "CM-6", "CM-7"],
        "attck_mitigations": ["M1054", "M1042"],
        "technique_ids":     ["T1543", "T1546", "T1059", "T1047"],
        "rationale": (
            "CM-6 (Configuration Settings) maps to M1054 (Software Configuration) "
            "to harden against T1543 (Create or Modify System Process) and T1546 "
            "(Event Triggered Execution). CM-7 (Least Functionality) maps to M1042 "
            "(Disable or Remove Feature or Program) to limit exposure from T1059 "
            "(Command and Scripting Interpreter) and T1047 (Windows Management "
            "Instrumentation) — both core to Volt Typhoon's LotL methodology."
        ),
    },
    {
        "mapping_id":        "XREF-009",
        "category":          "Script and Execution Control",
        "nist_controls":     ["CM-7", "CM-7(2)", "CM-7(5)"],
        "attck_mitigations": ["M1038", "M1026", "M1042"],
        "technique_ids":     ["T1059.001", "T1059.003", "T1047", "T1204.002"],
        "rationale": (
            "CM-7(2) (Prevent Use of Programs) and CM-7(5) (Authorized Software — "
            "Allowlisting) directly implement M1038 (Execution Prevention) to block "
            "unauthorized T1059.001 (PowerShell), T1059.003 (Windows Command Shell), "
            "T1047 (WMI), and T1204.002 (Malicious File) execution. Application "
            "allowlisting is the highest-confidence control against living-off-the-land "
            "abuse of built-in Windows tools."
        ),
    },

    # Network Security and Segmentation
    {
        "mapping_id":        "XREF-010",
        "category":          "Network Segmentation and Boundary Protection",
        "nist_controls":     ["SC-7", "SC-7(3)", "SC-7(5)", "SC-7(8)"],
        "attck_mitigations": ["M1030", "M1037"],
        "technique_ids":     ["T1090", "T1090.002", "T1021", "T1041", "T1048"],
        "rationale": (
            "SC-7 (Boundary Protection) and its sub-enhancements SC-7(3) (Access "
            "Points), SC-7(5) (Deny by Default), and SC-7(8) (Route Traffic to "
            "Authenticated Proxy Servers) map to M1030 (Network Segmentation) and "
            "M1037 (Filter Network Traffic). These controls limit lateral movement "
            "via T1021 (Remote Services), C2 via T1090.002 (External Proxy), and "
            "exfiltration via T1041/T1048. Critical for IT/OT boundary protection "
            "against Volt Typhoon pre-positioning."
        ),
    },

    # Malware Defense and Endpoint Protection
    {
        "mapping_id":        "XREF-011",
        "category":          "Malware Defense",
        "nist_controls":     ["SI-3", "SI-3(2)", "SI-3(10)"],
        "attck_mitigations": ["M1049", "M1045"],
        "technique_ids":     ["T1204", "T1059", "T1486", "T1561"],
        "rationale": (
            "SI-3 (Malware Protection) and SI-3(2) (Automatic Updates) map to "
            "M1049 (Antivirus/Antimalware) for detection of malicious payloads "
            "including T1486 (Data Encrypted for Impact — ransomware) and T1561 "
            "(Disk Wipe — wiper malware). SI-3(10) (Malicious Code Analysis) "
            "supports deeper behavioral analysis. M1045 (Code Signing) through "
            "CM-7(5) reduces execution of unsigned malicious binaries (T1204 — "
            "User Execution)."
        ),
    },

    # Incident Response
    {
        "mapping_id":        "XREF-012",
        "category":          "Incident Response Capability",
        "nist_controls":     ["IR-4", "IR-5", "IR-6", "IR-8"],
        "attck_mitigations": [],
        "technique_ids":     ["T1486", "T1485", "T1491"],
        "rationale": (
            "IR-4 (Incident Handling), IR-5 (Incident Monitoring), IR-6 (Incident "
            "Reporting), and IR-8 (Incident Response Plan) are the NIST 800-53 "
            "framework controls governing the incident response lifecycle described "
            "in NIST SP 800-61r2. While these controls do not map to specific ATT&CK "
            "mitigations (which are preventive), they govern organizational response "
            "to high-impact techniques including T1486 (ransomware), T1485 (data "
            "destruction), and T1491 (defacement). The IR control family corresponds "
            "to Phases 2-4 of the NIST IR lifecycle: Detection & Analysis, "
            "Containment/Eradication/Recovery, and Post-Incident Activity."
        ),
    },
    {
        "mapping_id":        "XREF-013",
        "category":          "Backup and Recovery",
        "nist_controls":     ["CP-9", "CP-9(1)", "CP-9(3)", "CP-10"],
        "attck_mitigations": ["M1053"],
        "technique_ids":     ["T1486", "T1485", "T1561.002"],
        "rationale": (
            "CP-9 (System Backup) with enhancements CP-9(1) (Testing for Reliability "
            "and Integrity) and CP-9(3) (Separate Storage for Critical Information) "
            "map to M1053 (Data Backup) — the definitive control against T1486 "
            "(Data Encrypted for Impact — ransomware), T1485 (Data Destruction), "
            "and T1561.002 (Disk Structure Wipe). CP-10 (System Recovery) governs "
            "the restoration phase of IR. Immutable, offline backups tested regularly "
            "are the primary recovery mechanism against ransomware and wiper attacks."
        ),
    },

    # Privileged Access and Credential Security
    {
        "mapping_id":        "XREF-014",
        "category":          "Privileged Access Management",
        "nist_controls":     ["AC-6(1)", "AC-6(2)", "AC-6(5)", "AC-6(9)"],
        "attck_mitigations": ["M1026", "M1018"],
        "technique_ids":     ["T1003", "T1003.001", "T1078.003", "T1548.002"],
        "rationale": (
            "AC-6 enhancements target privileged access: AC-6(1) (Authorize Access "
            "to Security Functions), AC-6(2) (Non-Privileged Access for "
            "Non-Security Functions), AC-6(5) (Privileged Accounts), and AC-6(9) "
            "(Log Use of Privileged Functions) all map to M1026 (Privileged Account "
            "Management). These directly mitigate T1003 (OS Credential Dumping) "
            "including T1003.001 (LSASS Memory) used by Volt Typhoon, and T1548.002 "
            "(Bypass User Account Control). Limiting LSASS read access requires "
            "privileged account restrictions enforced through these controls."
        ),
    },

    # Supply Chain and Third-Party Risk
    {
        "mapping_id":        "XREF-015",
        "category":          "Supply Chain and Third-Party Security",
        "nist_controls":     ["SR-3", "SR-5", "SR-6", "SA-9"],
        "attck_mitigations": ["M1016"],
        "technique_ids":     ["T1195", "T1195.002", "T1199", "T1584"],
        "rationale": (
            "SR-3 (Supply Chain Controls), SR-5 (Acquisition Strategies), SR-6 "
            "(Supplier Assessments), and SA-9 (External System Services) collectively "
            "implement M1016 (Vulnerability Scanning) requirements for third-party "
            "components and map to supply chain attacks T1195 (Supply Chain "
            "Compromise) and T1199 (Trusted Relationship). These controls are "
            "particularly relevant for T1584 (Compromise Infrastructure) scenarios "
            "where adversaries leverage compromised third-party infrastructure as "
            "seen in Volt Typhoon KV Botnet operations."
        ),
    },
    {
        "mapping_id":        "XREF-016",
        "category":          "Data Protection and Exfiltration Prevention",
        "nist_controls":     ["SC-28", "AC-4", "AC-4(17)", "SI-12"],
        "attck_mitigations": ["M1041", "M1057"],
        "technique_ids":     ["T1530", "T1537", "T1567", "T1041", "T1048"],
        "rationale": (
            "AC-4 (Information Flow Enforcement) and AC-4(17) (Domain Authentication) "
            "map to M1057 (Data Loss Prevention) to detect and prevent data "
            "exfiltration techniques including T1530 (Data from Cloud Storage — "
            "Scattered Spider), T1537 (Transfer to Cloud Account), T1567 "
            "(Exfiltration to Web Service), and T1041/T1048. SC-28 (Protection of "
            "Information at Rest) and SI-12 (Information Management and Retention) "
            "supplement with M1041 (Encrypt Sensitive Information) to limit value "
            "of exfiltrated data."
        ),
    },
]


def build_crossref_records() -> list[dict]:
    """Return the NIST ↔ ATT&CK cross-reference records ready for embedding."""
    print(
        f"Prepared {len(NIST_ATTCK_CROSSREF)} NIST 800-53 ↔ ATT&CK "
        f"cross-reference mappings"
    )
    return NIST_ATTCK_CROSSREF


# MAIN

def main():
    print("\n" + "═" * 64)
    print("  Multi-Framework Downloader + Parser  (v2)")
    print("  ATT&CK  •  CISA Advisories  •  NIST 800-53  •  XREF Map")
    print("═" * 64 + "\n")

    # 1 & 2. ATT&CK techniques + mitigations
    print("[ 1/5 ]  MITRE ATT&CK Enterprise STIX bundle")
    bundle = _download(STIX_URL, STIX_LOCAL, "ATT&CK STIX bundle")

    techniques = parse_techniques(bundle)
    with open(OUT_TECHNIQUES, "w") as f:
        json.dump(techniques, f, indent=2)
    print(f"         💾  Saved {OUT_TECHNIQUES}\n")

    print("[ 2/5 ]  ATT&CK Mitigations (from same STIX bundle)")
    mitigations = parse_mitigations(bundle)
    with open(OUT_MITIGATIONS, "w") as f:
        json.dump(mitigations, f, indent=2)
    print(f"         💾  Saved {OUT_MITIGATIONS}\n")

    # 3. CISA advisories
    print("[ 3/5 ]  CISA Advisories (AA23-144A, AA24-038A, AA23-061A, "
          "AA23-320A, AA24-190A)")
    cisa_records = build_cisa_records()
    with open(OUT_CISA, "w") as f:
        json.dump(cisa_records, f, indent=2)
    print(f"         💾  Saved {OUT_CISA}\n")

    # 4. NIST 800-53
    print("[ 4/5 ]  NIST SP 800-53 rev5 Controls")
    nist_catalog  = download_nist(NIST_URL, NIST_LOCAL)
    nist_controls = parse_nist_controls(nist_catalog)
    with open(OUT_NIST, "w") as f:
        json.dump(nist_controls, f, indent=2)
    print(f"         💾  Saved {OUT_NIST}\n")

    # 5. NIST ↔ ATT&CK cross-reference
    print("[ 5/5 ]  NIST 800-53 ↔ ATT&CK Cross-Reference Map  (NEW)")
    crossref = build_crossref_records()
    with open(OUT_CROSSREF, "w") as f:
        json.dump(crossref, f, indent=2)
    print(f"         💾  Saved {OUT_CROSSREF}\n")

    # Summary
    print("  All frameworks downloaded and parsed successfully")
    print(f"  • ATT&CK techniques     : {len(techniques):>4}  → {OUT_TECHNIQUES}")
    print(f"  • ATT&CK mitigations    : {len(mitigations):>4}  → {OUT_MITIGATIONS}")
    print(f"  • CISA advisory chunks  : {len(cisa_records):>4}  → {OUT_CISA}")
    print(f"  • NIST 800-53 controls  : {len(nist_controls):>4}  → {OUT_NIST}")
    print(f"  • NIST ↔ ATT&CK xref   : {len(crossref):>4}  → {OUT_CROSSREF}")
    print()
    print("Advisory coverage summary:")
    advisory_ids = sorted({c["advisory_id"] for c in cisa_records})
    for aid in advisory_ids:
        chunks  = [c for c in cisa_records if c["advisory_id"] == aid]
        actor   = chunks[0].get("threat_actor", "Unknown")
        n_techs = sum(len(c["technique_ids"]) for c in chunks)
        print(f"    {aid}  ({actor})  "
              f"{len(chunks)} chunks, {n_techs} technique references")
    print()


if __name__ == "__main__":
    main()
