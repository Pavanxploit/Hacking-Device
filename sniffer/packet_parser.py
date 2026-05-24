"""
packet_parser.py — Parse raw Scapy 802.11 frames into clean Python dicts.
Handles: Beacon, Probe Request, Probe Response, Deauth, Disassoc, EAPOL.
All parsers return None for frames they can't handle — callers filter None.
"""

import time
import logging
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
    Dot11Deauth, Dot11Disas, Dot11Elt,
)
from scapy.layers.eap import EAPOL
from scapy.packet import Packet

log = logging.getLogger("wifighost.parser")

# 802.11 frame type/subtype constants
DOT11_TYPE_MGMT  = 0
DOT11_SUBTYPE_BEACON       = 8
DOT11_SUBTYPE_PROBE_REQ    = 4
DOT11_SUBTYPE_PROBE_RESP   = 5
DOT11_SUBTYPE_DEAUTH       = 12
DOT11_SUBTYPE_DISASSOC     = 10
DOT11_SUBTYPE_AUTH         = 11


def _get_rssi(pkt: Packet) -> int:
    """Extract RSSI from RadioTap header, return 0 if unavailable."""
    try:
        from scapy.layers.radiohead import RadioTap
        if pkt.haslayer(RadioTap):
            return int(pkt[RadioTap].dBm_AntSignal or 0)
    except Exception:
        pass
    return 0


def _get_ssid(pkt: Packet) -> str:
    """Extract SSID from Dot11Elt chain, return '' for hidden SSIDs."""
    try:
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 0:  # SSID element
                raw = elt.info
                return raw.decode("utf-8", errors="replace") if raw else ""
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    except Exception:
        pass
    return ""


def _get_channel_from_elt(pkt: Packet) -> int:
    """Extract channel from DS Parameter Set element (ID=3)."""
    try:
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 3 and elt.info:
                return int.from_bytes(elt.info, "big")
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    except Exception:
        pass
    return 0


def _capabilities(pkt: Packet) -> dict:
    """Parse capability flags from Beacon/ProbeResp frames."""
    caps = {"wpa": False, "wpa2": False, "wps": False, "open": True}
    try:
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x01":
                caps["wpa"]  = True
                caps["open"] = False
            if elt.ID == 48:   # RSN (WPA2/WPA3)
                caps["wpa2"] = True
                caps["open"] = False
            if elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x04":
                caps["wps"] = True
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    except Exception:
        pass
    return caps


# ─── Frame parsers ────────────────────────────────────────────────────────

def parse_beacon(pkt: Packet) -> dict | None:
    """Parse a Beacon frame → AP record."""
    if not (pkt.haslayer(Dot11) and pkt.haslayer(Dot11Beacon)):
        return None
    try:
        dot11 = pkt[Dot11]
        caps  = _capabilities(pkt)
        return {
            "frame_type": "beacon",
            "ssid":       _get_ssid(pkt),
            "bssid":      dot11.addr3 or dot11.addr2 or "",
            "src_mac":    dot11.addr2 or "",
            "rssi":       _get_rssi(pkt),
            "channel":    _get_channel_from_elt(pkt),
            "ts":         time.time(),
            "wpa":        caps["wpa"],
            "wpa2":       caps["wpa2"],
            "wps":        caps["wps"],
            "open":       caps["open"],
        }
    except Exception as e:
        log.debug(f"parse_beacon error: {e}")
        return None


def parse_probe_request(pkt: Packet) -> dict | None:
    """Parse a Probe Request → client record (what SSIDs a device is hunting for)."""
    if not (pkt.haslayer(Dot11) and pkt.haslayer(Dot11ProbeReq)):
        return None
    try:
        dot11 = pkt[Dot11]
        ssid  = _get_ssid(pkt)
        return {
            "frame_type":   "probe_req",
            "client_mac":   dot11.addr2 or "",
            "ssid_wanted":  ssid,           # empty = wildcard probe
            "rssi":         _get_rssi(pkt),
            "ts":           time.time(),
        }
    except Exception as e:
        log.debug(f"parse_probe_request error: {e}")
        return None


def parse_probe_response(pkt: Packet) -> dict | None:
    """Parse a Probe Response — AP responding to probe, useful for rogue AP detection."""
    if not (pkt.haslayer(Dot11) and pkt.haslayer(Dot11ProbeResp)):
        return None
    try:
        dot11 = pkt[Dot11]
        caps  = _capabilities(pkt)
        return {
            "frame_type": "probe_resp",
            "ssid":       _get_ssid(pkt),
            "bssid":      dot11.addr2 or "",
            "client_mac": dot11.addr1 or "",
            "rssi":       _get_rssi(pkt),
            "channel":    _get_channel_from_elt(pkt),
            "ts":         time.time(),
            "open":       caps["open"],
        }
    except Exception as e:
        log.debug(f"parse_probe_response error: {e}")
        return None


def parse_deauth(pkt: Packet) -> dict | None:
    """
    Parse a Deauthentication or Disassociation frame.
    These are the key frames in:
      - Deauth flood attacks (many in rapid succession)
      - Evil twin setup (attacker kicks clients off real AP first)
    """
    has_deauth  = pkt.haslayer(Dot11Deauth)
    has_disassoc = pkt.haslayer(Dot11Disas)
    if not (pkt.haslayer(Dot11) and (has_deauth or has_disassoc)):
        return None
    try:
        dot11     = pkt[Dot11]
        layer     = pkt[Dot11Deauth] if has_deauth else pkt[Dot11Disas]
        reason    = int(layer.reason) if hasattr(layer, "reason") else 0

        # Reason codes reference:
        # 1=Unspecified, 2=Auth expired, 3=Leaving, 4=Inactivity
        # 6=Class2 from unauthed, 7=Class3 from unassoc — most common in attacks
        reason_str = {
            1: "Unspecified",
            2: "Auth no longer valid",
            3: "Deauth: station leaving",
            4: "Inactivity timeout",
            6: "Class 2 from unauthed",
            7: "Class 3 from unassoc",
        }.get(reason, f"Code {reason}")

        return {
            "frame_type":  "deauth" if has_deauth else "disassoc",
            "src_mac":     dot11.addr2 or "",   # who sent it
            "dst_mac":     dot11.addr1 or "",   # who it targets (FF:FF:FF = broadcast)
            "bssid":       dot11.addr3 or "",   # AP BSSID
            "reason_code": reason,
            "reason_str":  reason_str,
            "broadcast":   (dot11.addr1 == "ff:ff:ff:ff:ff:ff"),
            "rssi":        _get_rssi(pkt),
            "ts":          time.time(),
        }
    except Exception as e:
        log.debug(f"parse_deauth error: {e}")
        return None


def parse_eapol(pkt: Packet) -> dict | None:
    """
    Parse EAPOL (WPA handshake) frames.
    PMKID attacks use the first EAPOL frame (Message 1 of 4-way handshake).
    Detecting EAPOL where no prior auth is seen = suspicious.
    """
    if not (pkt.haslayer(Dot11) and pkt.haslayer(EAPOL)):
        return None
    try:
        dot11 = pkt[Dot11]
        eapol = pkt[EAPOL]
        return {
            "frame_type": "eapol",
            "src_mac":    dot11.addr2 or "",
            "dst_mac":    dot11.addr1 or "",
            "bssid":      dot11.addr3 or "",
            "eapol_type": int(eapol.type),
            "rssi":       _get_rssi(pkt),
            "ts":         time.time(),
        }
    except Exception as e:
        log.debug(f"parse_eapol error: {e}")
        return None


def parse_auth(pkt: Packet) -> dict | None:
    """
    Parse Authentication frames.
    Rapid auth frames from unknown clients = possible PMKID or brute force.
    """
    if not pkt.haslayer(Dot11):
        return None
    dot11 = pkt[Dot11]
    if dot11.type != DOT11_TYPE_MGMT or dot11.subtype != DOT11_SUBTYPE_AUTH:
        return None
    try:
        return {
            "frame_type": "auth",
            "src_mac":    dot11.addr2 or "",
            "dst_mac":    dot11.addr1 or "",
            "bssid":      dot11.addr3 or "",
            "rssi":       _get_rssi(pkt),
            "ts":         time.time(),
        }
    except Exception as e:
        log.debug(f"parse_auth error: {e}")
        return None


def parse_frame(pkt: Packet) -> dict | None:
    """
    Master dispatcher — try all parsers in priority order.
    Returns first non-None result, or None for unrecognised frames.
    """
    parsers = [
        parse_deauth,
        parse_eapol,
        parse_beacon,
        parse_probe_request,
        parse_probe_response,
        parse_auth,
    ]
    for parser in parsers:
        result = parser(pkt)
        if result is not None:
            return result
    return None
