"""
oui_lookup.py — Resolve MAC address OUI prefix to vendor name.
Uses a local CSV copy of the IEEE OUI registry (data/oui.csv).
Falls back to "Unknown" — no network call required.
"""

import csv
import os
import logging
from functools import lru_cache

log = logging.getLogger("wifighost.oui")

# Path to the OUI database CSV relative to project root
_DEFAULT_OUI_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "oui.csv"
)

# In-memory dict: "AA:BB:CC" → "Vendor Name"
_oui_db: dict[str, str] = {}
_loaded = False


def load_oui_db(path: str = _DEFAULT_OUI_PATH) -> int:
    """
    Load the OUI CSV into memory.
    CSV format expected: Assignment,Organization Name,...
    Returns number of entries loaded.

    Download the latest OUI file with:
        wget -O data/oui.csv https://standards-oui.ieee.org/oui/oui.csv
    """
    global _oui_db, _loaded
    _oui_db = {}

    if not os.path.exists(path):
        log.warning(
            f"OUI database not found at {path}. "
            "Run: wget -O data/oui.csv https://standards-oui.ieee.org/oui/oui.csv"
        )
        _loaded = True
        return 0

    try:
        with open(path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw = row.get("Assignment", "").strip().upper()
                vendor = row.get("Organization Name", "Unknown").strip()
                if len(raw) == 6:
                    # Format as "AA:BB:CC"
                    key = ":".join(raw[i:i+2] for i in range(0, 6, 2))
                    _oui_db[key] = vendor
    except Exception as e:
        log.error(f"Failed to load OUI database: {e}")

    _loaded = True
    log.info(f"OUI database loaded: {len(_oui_db)} vendors")
    return len(_oui_db)


@lru_cache(maxsize=4096)
def lookup(mac: str) -> str:
    """
    Return the vendor name for a MAC address.
    Accepts formats: "AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", "aabbccddeeff"

    Returns "Unknown" if not found.
    """
    if not _loaded:
        load_oui_db()

    # Normalise to uppercase colon-separated
    mac_clean = mac.upper().replace("-", ":").replace(".", ":")
    # Remove any extra separators and reformat
    digits = mac_clean.replace(":", "")
    if len(digits) < 6:
        return "Unknown"

    oui = ":".join(digits[i:i+2] for i in range(0, 6, 2))
    return _oui_db.get(oui, "Unknown")


def is_randomised_mac(mac: str) -> bool:
    """
    Detect locally administered (randomised) MAC addresses.
    Bit 1 of first octet is set for locally administered MACs.
    Modern phones randomise MACs when probing — important signal.
    """
    try:
        first_octet = int(mac.replace(":", "").replace("-", "")[:2], 16)
        return bool(first_octet & 0x02)
    except ValueError:
        return False
