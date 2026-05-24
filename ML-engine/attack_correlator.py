"""
attack_correlator.py — Multi-event attack chain correlator.

Real Wi-Fi attacks don't happen in isolation — they follow sequences:

  Evil Twin attack chain:
    1. Deauth flood (kick clients off real AP)
    2. Rogue AP appears with same SSID
    3. Clients probe for lost network
    4. Clients connect to rogue AP

  PMKID attack chain:
    1. Target AP scanned
    2. EAPOL M1 captured without deauth
    3. Handshake saved for offline cracking

  Karma attack chain:
    1. Probe requests collected (device histories leaked)
    2. Rogue AP mirrors client's desired SSIDs
    3. Client connects to karma AP

The correlator maintains a time-ordered event log and uses pattern
matching to identify when multiple events form a coordinated attack.
When a chain is confirmed, the threat score is elevated and the alert
is annotated with the full chain context.
"""

import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field

log = logging.getLogger("wifighost.correlator")

# How long an event stays in the correlation window
CHAIN_WINDOW_SEC = 120   # 2 minutes


@dataclass
class AttackChain:
    chain_type:   str              # "EVIL_TWIN_CHAIN" | "PMKID_CHAIN" | "KARMA_CHAIN"
    events:       list[dict]       # ordered list of contributing events
    bssid:        str              # target/attacker BSSID
    ssid:         str              # target SSID
    confidence:   int              # 0–100, elevated vs individual events
    started_at:   float = field(default_factory=time.time)
    description:  str = ""


class AttackCorrelator:
    """
    Feed events (sniffer alerts + ML results) via feed().
    Call get_chains() to retrieve confirmed attack chains.

    The correlator acts as a post-processor — it doesn't replace
    individual alerts, it ADDS chain-level alerts on top of them.
    """

    def __init__(self, window_sec: float = CHAIN_WINDOW_SEC):
        self.window_sec = window_sec
        # bssid → list of recent events
        self._events_by_bssid: dict[str, list] = defaultdict(list)
        # ssid → list of recent events
        self._events_by_ssid:  dict[str, list] = defaultdict(list)
        # All events (for pattern matching across BSSIDs)
        self._all_events: list[dict] = []
        # Output queue
        self._chains: list[AttackChain] = []
        # Already-fired chain keys
        self._fired: set[str] = set()

    def feed(self, event: dict):
        """
        Feed one event. Can be a sniffer alert dict or ML ThreatResult dict.
        Events must have at minimum: alert_type or attack_type, ts, bssid.
        """
        ts    = event.get("ts", time.time())
        bssid = event.get("bssid", "").lower()
        ssid  = event.get("ssid", "").lower()
        atype = event.get("alert_type") or event.get("attack_type") or ""

        tagged = {**event, "_bssid": bssid, "_ssid": ssid,
                  "_atype": atype.upper(), "_ts": ts}

        self._all_events.append(tagged)
        if bssid:
            self._events_by_bssid[bssid].append(tagged)
        if ssid:
            self._events_by_ssid[ssid].append(tagged)

        self._evict_old()
        self._check_evil_twin_chain(bssid, ssid)
        self._check_pmkid_chain(bssid)
        self._check_karma_chain(bssid, ssid)

    # ─── Chain detectors ───────────────────────────────────────────────────

    def _check_evil_twin_chain(self, bssid: str, ssid: str):
        """
        Evil Twin chain:
          DEAUTH_FLOOD + (EVIL_TWIN or ROGUE_AP) from same/nearby BSSID
          with same SSID, within window.
        """
        if not ssid:
            return

        ssid_events = self._events_by_ssid.get(ssid, [])
        atypes = {e["_atype"] for e in ssid_events}

        has_deauth     = any(t in atypes for t in
                             ("DEAUTH_FLOOD","BROADCAST_DEAUTH","EVIL_TWIN_PREP"))
        has_rogue      = any(t in atypes for t in ("EVIL_TWIN","ROGUE_AP"))

        if has_deauth and has_rogue:
            key = f"evil_twin_chain_{ssid}"
            if key not in self._fired:
                chain_events = [e for e in ssid_events
                                if e["_atype"] in
                                ("DEAUTH_FLOOD","BROADCAST_DEAUTH",
                                 "EVIL_TWIN_PREP","EVIL_TWIN","ROGUE_AP")]
                confidence = 92
                chain = AttackChain(
                    chain_type  = "EVIL_TWIN_CHAIN",
                    events      = chain_events,
                    bssid       = bssid,
                    ssid        = ssid,
                    confidence  = confidence,
                    description = (
                        f"Coordinated evil twin attack on SSID '{ssid}': "
                        f"deauthentication flood detected followed by rogue AP "
                        f"broadcasting the same SSID. Clients are being redirected."
                    ),
                )
                self._chains.append(chain)
                self._fired.add(key)
                log.warning(
                    f"[CHAIN] EVIL_TWIN_CHAIN on ssid='{ssid}' "
                    f"events={len(chain_events)} conf={confidence}%"
                )

    def _check_pmkid_chain(self, bssid: str):
        """
        PMKID chain:
          PMKID_ATTEMPT + HANDSHAKE_CAPTURE from same BSSID in window.
        """
        if not bssid:
            return
        events = self._events_by_bssid.get(bssid, [])
        atypes = {e["_atype"] for e in events}

        if "PMKID_ATTEMPT" in atypes and "HANDSHAKE_CAPTURE" in atypes:
            key = f"pmkid_chain_{bssid}"
            if key not in self._fired:
                chain_events = [e for e in events
                                if e["_atype"] in ("PMKID_ATTEMPT","HANDSHAKE_CAPTURE")]
                ssid = next((e.get("ssid","") for e in chain_events), "")
                chain = AttackChain(
                    chain_type  = "PMKID_CHAIN",
                    events      = chain_events,
                    bssid       = bssid,
                    ssid        = ssid,
                    confidence  = 88,
                    description = (
                        f"WPA2 handshake capture chain detected against bssid={bssid}: "
                        f"PMKID frame collected followed by full 4-way handshake. "
                        f"Attacker likely running hashcat/john for offline password cracking."
                    ),
                )
                self._chains.append(chain)
                self._fired.add(key)
                log.warning(f"[CHAIN] PMKID_CHAIN bssid={bssid}")

    def _check_karma_chain(self, bssid: str, ssid: str):
        """
        Karma chain:
          SSID_HARVESTING + KARMA_AP from same bssid/area.
        """
        # Look globally — karma AP may use different BSSID than probe collector
        all_atypes = {e["_atype"] for e in self._all_events}

        if "SSID_HARVESTING" in all_atypes and "KARMA_AP" in all_atypes:
            key = "karma_chain_global"
            if key not in self._fired:
                harvests = [e for e in self._all_events if e["_atype"] == "SSID_HARVESTING"]
                karmas   = [e for e in self._all_events if e["_atype"] == "KARMA_AP"]
                chain = AttackChain(
                    chain_type  = "KARMA_CHAIN",
                    events      = harvests + karmas,
                    bssid       = bssid,
                    ssid        = ssid,
                    confidence  = 85,
                    description = (
                        "Karma attack chain in progress: probe request harvesting detected "
                        "followed by a rogue AP responding to matching SSIDs. "
                        "An attacker is impersonating known networks to intercept client traffic."
                    ),
                )
                self._chains.append(chain)
                self._fired.add(key)
                log.warning("[CHAIN] KARMA_CHAIN detected globally")

    def get_chains(self) -> list[AttackChain]:
        """Drain and return all confirmed attack chains."""
        out = list(self._chains)
        self._chains.clear()
        return out

    def get_event_summary(self) -> dict:
        """Return a summary of events in the current window."""
        events = self._evict_old()
        by_type: dict[str, int] = defaultdict(int)
        for e in self._all_events:
            by_type[e["_atype"]] += 1
        return {
            "event_count": len(self._all_events),
            "by_type":     dict(by_type),
            "window_sec":  self.window_sec,
        }

    def _evict_old(self) -> list:
        cutoff = time.time() - self.window_sec
        self._all_events = [e for e in self._all_events if e["_ts"] >= cutoff]
        for bssid in list(self._events_by_bssid):
            self._events_by_bssid[bssid] = [
                e for e in self._events_by_bssid[bssid] if e["_ts"] >= cutoff
            ]
            if not self._events_by_bssid[bssid]:
                del self._events_by_bssid[bssid]
        for ssid in list(self._events_by_ssid):
            self._events_by_ssid[ssid] = [
                e for e in self._events_by_ssid[ssid] if e["_ts"] >= cutoff
            ]
            if not self._events_by_ssid[ssid]:
                del self._events_by_ssid[ssid]
        return self._all_events

    def reset(self):
        self._all_events.clear()
        self._events_by_bssid.clear()
        self._events_by_ssid.clear()
        self._fired.clear()
        self._chains.clear()
