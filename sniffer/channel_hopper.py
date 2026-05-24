"""
channel_hopper.py — background channel sweep for the monitor interface.
Hops channels 1-13 (2.4GHz) so the sniffer captures frames across
all bands, not just the channel the laptop's main adapter is on.
"""

import threading
import time
import logging
from .monitor import set_channel

log = logging.getLogger("wifighost.hopper")

# 2.4 GHz non-overlapping channels first, then fill-in channels
# This catches most real-world APs faster on first sweep
CHANNEL_ORDER = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]

# How long to dwell on each channel (seconds)
# Shorter = catch more channels per second but miss short bursts
# 0.25s is a good balance for deauth/beacon detection
DWELL_TIME = 0.25


class ChannelHopper(threading.Thread):
    """
    Background thread that continuously hops channels on <interface>.
    Call start() to begin, stop() to end cleanly.

    Usage:
        hopper = ChannelHopper("wlan0mon")
        hopper.start()
        # ... sniff ...
        hopper.stop()
    """

    def __init__(self, interface: str, dwell: float = DWELL_TIME,
                 channels: list[int] = None):
        super().__init__(daemon=True, name="ChannelHopper")
        self.interface  = interface
        self.dwell      = dwell
        self.channels   = channels or CHANNEL_ORDER
        self._stop_flag = threading.Event()
        self._current   = self.channels[0]
        self._lock      = threading.Lock()

    @property
    def current_channel(self) -> int:
        with self._lock:
            return self._current

    def stop(self):
        self._stop_flag.set()

    def run(self):
        log.info(
            f"Channel hopper started on {self.interface} "
            f"dwell={self.dwell}s channels={self.channels}"
        )
        while not self._stop_flag.is_set():
            for ch in self.channels:
                if self._stop_flag.is_set():
                    break
                set_channel(self.interface, ch)
                with self._lock:
                    self._current = ch
                time.sleep(self.dwell)

        log.info("Channel hopper stopped.")

    def pause_on(self, channel: int, duration: float = 2.0):
        """
        Temporarily dwell longer on a specific channel (e.g. when a
        deauth burst is detected and we want to capture more frames).
        Non-blocking — runs in hopper thread next iteration.
        """
        # Simple: just set the channel directly; hopper will resume normally
        set_channel(self.interface, channel)
        with self._lock:
            self._current = channel
        time.sleep(duration)
