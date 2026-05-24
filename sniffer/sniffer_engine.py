"""
sniffer_engine.py — Master sniffer orchestrator for WiFiGhost AI.

Wires together:
  monitor.py        → enable wlan0mon
  channel_hopper.py → sweep channels 1-13
  packet_parser.py  → parse 802.11 frames
  deauth_detector   → flood / evil-twin-prep
  beacon_flood      → beacon flood / karma / evil-twin
  probe_harvester   → probe burst / SSID harvesting
  pmkid_watcher     → PMKID attempts / handshake capture
  oui_lookup        → vendor names

Outputs alerts to a thread-safe queue that the backend reads.
Run as a subprocess/thread alongside the Flask backend.

Usage (standalone, for testing):
    sudo python3 -m sniffer.sniffer_engine --iface wlan0 --verbose

Usage (from backend):
    from sniffer import SnifferEngine
    engine = SnifferEngine(interface="wlan0", alert_queue=q)
    engine.start()
    ...
    engine.stop()
"""

import argparse
import logging
import queue
import signal
import sys
import threading
import time
from dataclasses import asdict

from scapy.all import sniff, conf as scapy_conf

from .monitor        import enable_monitor_mode, disable_monitor_mode, load_oui_db
from .channel_hopper import ChannelHopper
from .packet_parser  import parse_frame
from .deauth_detector import DeauthDetector
from .beacon_flood    import BeaconFloodDetector
from .probe_harvester import ProbeHarvester
from .pmkid_watcher   import PMKIDWatcher
from .oui_lookup      import load_oui_db

log = logging.getLogger("wifighost.engine")

# Suppress scapy's verbose output
scapy_conf.verb = 0


class SnifferEngine:
    """
    Full passive Wi-Fi threat detection engine.
    Thread-safe: alert_queue receives dicts that the backend can serialise.
    """

    def __init__(self,
                 interface:    str         = "wlan0",
                 alert_queue:  queue.Queue = None,
                 trusted_ssids: dict       = None,
                 verbose:      bool        = False):
        """
        interface    : base Wi-Fi interface (e.g. 'wlan0')
                       Engine will create wlan0mon automatically.
        alert_queue  : thread-safe queue.Queue — alerts are put() here.
                       If None, alerts are only logged.
        trusted_ssids: dict of {ssid: [bssid, ...]} from baseline.json
        verbose      : enable DEBUG logging
        """
        self.interface     = interface
        self.alert_queue   = alert_queue or queue.Queue()
        self.trusted_ssids = trusted_ssids or {}
        self.verbose       = verbose

        self._mon_iface:   str | None         = None
        self._hopper:      ChannelHopper | None = None
        self._sniff_thread: threading.Thread | None = None
        self._running      = threading.Event()

        # Detection modules
        trusted_bssid_set = set()
        for bssids in self.trusted_ssids.values():
            trusted_bssid_set.update(b.lower() for b in bssids)

        self._deauth   = DeauthDetector(trusted_bssids=trusted_bssid_set)
        self._beacon   = BeaconFloodDetector()
        self._probe    = ProbeHarvester()
        self._pmkid    = PMKIDWatcher()

        # Register trusted SSID → BSSID pairs in beacon detector
        for ssid, bssids in self.trusted_ssids.items():
            for bssid in bssids:
                self._beacon.register_trusted_ap(ssid, bssid)

        # Stats
        self._stats = {
            "frames_total":   0,
            "frames_parsed":  0,
            "alerts_fired":   0,
            "started_at":     None,
        }

    # ─── Public API ────────────────────────────────────────────────────────

    def start(self):
        """Enable monitor mode, start channel hopper, start sniff loop."""
        log.info(f"SnifferEngine starting on {self.interface}...")

        load_oui_db()

        self._mon_iface = enable_monitor_mode(self.interface)
        log.info(f"Monitor interface: {self._mon_iface}")

        self._hopper = ChannelHopper(self._mon_iface)
        self._hopper.start()

        self._running.set()
        self._stats["started_at"] = time.time()

        self._sniff_thread = threading.Thread(
            target=self._sniff_loop,
            name="SnifferLoop",
            daemon=True,
        )
        self._sniff_thread.start()
        log.info("SnifferEngine running.")

    def stop(self):
        """Stop sniffing, tear down monitor mode."""
        log.info("SnifferEngine stopping...")
        self._running.clear()

        if self._hopper:
            self._hopper.stop()

        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=5)

        if self._mon_iface:
            disable_monitor_mode(self._mon_iface, self.interface)

        log.info(
            f"SnifferEngine stopped. Stats: "
            f"frames={self._stats['frames_total']} "
            f"parsed={self._stats['frames_parsed']} "
            f"alerts={self._stats['alerts_fired']}"
        )

    def get_stats(self) -> dict:
        uptime = time.time() - (self._stats["started_at"] or time.time())
        return {**self._stats, "uptime_sec": round(uptime, 1)}

    # ─── Sniff loop ────────────────────────────────────────────────────────

    def _sniff_loop(self):
        """Blocking Scapy sniff — runs in its own thread."""
        while self._running.is_set():
            try:
                sniff(
                    iface=self._mon_iface,
                    prn=self._handle_packet,
                    store=False,
                    timeout=2,           # yield every 2s so we can check _running
                    monitor=True,
                )
            except OSError as e:
                log.error(f"Sniff error: {e}")
                time.sleep(1)

    # ─── Packet handler ────────────────────────────────────────────────────

    def _handle_packet(self, pkt):
        self._stats["frames_total"] += 1

        frame = parse_frame(pkt)
        if frame is None:
            return

        self._stats["frames_parsed"] += 1
        ft = frame["frame_type"]

        # Route to appropriate detector(s)
        if ft in ("deauth", "disassoc"):
            self._deauth.feed(frame)

        elif ft == "beacon":
            self._beacon.feed(frame)
            # Notify deauth detector so it can correlate evil-twin-prep
            self._deauth.notify_beacon(
                frame["bssid"], frame["ssid"], frame["channel"]
            )

        elif ft == "probe_req":
            self._probe.feed(frame)

        elif ft == "eapol":
            self._pmkid.feed(frame)

        elif ft == "auth":
            self._pmkid.notify_auth(frame["src_mac"], frame["bssid"])

        # Drain alerts from all detectors
        self._drain_alerts()

    # ─── Alert draining ────────────────────────────────────────────────────

    def _drain_alerts(self):
        all_alerts = (
            self._deauth.get_alerts() +
            self._beacon.get_alerts() +
            self._probe.get_alerts()  +
            self._pmkid.get_alerts()
        )
        for alert in all_alerts:
            self._stats["alerts_fired"] += 1
            payload = self._format_alert(alert)
            log.info(
                f"[ALERT] {payload['alert_type']} "
                f"conf={payload['confidence']}% "
                f"bssid={payload.get('bssid','?')}"
            )
            try:
                self.alert_queue.put_nowait(payload)
            except queue.Full:
                log.warning("Alert queue full — dropping alert")

    def _format_alert(self, alert) -> dict:
        """Convert dataclass alert to a JSON-serialisable dict."""
        d = asdict(alert) if hasattr(alert, "__dataclass_fields__") else dict(alert)
        d["source"]   = "sniffer"
        d["iface"]    = self._mon_iface
        d["channel"]  = self._hopper.current_channel if self._hopper else 0
        return d


# ─── Standalone entry point ────────────────────────────────────────────────

def _main():
    parser = argparse.ArgumentParser(description="WiFiGhost AI — sniffer engine")
    parser.add_argument("--iface",   default="wlan0",  help="Base Wi-Fi interface")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Load baseline from file if available
    import json, os
    baseline_path = os.path.join(os.path.dirname(__file__), "..", "data", "baseline.json")
    trusted = {}
    if os.path.exists(baseline_path):
        with open(baseline_path) as f:
            trusted = json.load(f)
        log.info(f"Loaded baseline: {len(trusted)} trusted SSIDs")

    alert_q = queue.Queue(maxsize=500)
    engine  = SnifferEngine(
        interface    = args.iface,
        alert_queue  = alert_q,
        trusted_ssids = trusted,
        verbose      = args.verbose,
    )

    # Graceful shutdown on Ctrl+C
    def _sigint(sig, frame):
        print("\n[!] Stopping...")
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sigint)

    engine.start()

    # Print alerts to stdout when running standalone
    print("[*] Sniffer running. Ctrl+C to stop.\n")
    while True:
        try:
            alert = alert_q.get(timeout=1)
            print(
                f"  [{alert['alert_type']}] "
                f"conf={alert['confidence']}% "
                f"bssid={alert.get('bssid','?')} "
                f"ch={alert.get('channel','?')}"
            )
        except queue.Empty:
            pass


if __name__ == "__main__":
    _main()
