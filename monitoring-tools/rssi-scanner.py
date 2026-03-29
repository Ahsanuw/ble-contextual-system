"""
================================================================
  BLE Beacon Monitor — Energy-Efficient Presence Detection
  Compatible with beacon_main.c firmware (ESP-IDF v5.x)
================================================================

  Features:
  - Multi-beacon tracking (one row per device)
  - Kalman filter for RSSI smoothing (replaces moving average)
  - HMAC-SHA256 payload verification
  - Room / Near / Far / No Signal classification
  - Configurable thresholds
  - Clean Rich UI with color-coded states
  - CSV logging (optional)

  Requirements:
      pip install bleak rich

  Usage:
      python ble_monitor.py
      python ble_monitor.py --target hackathon --log
      python ble_monitor.py --room -60 --near -75 --timeout 5
================================================================
"""

import asyncio
import argparse
import struct
import hmac
import hashlib
import time
import csv
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

# ================================================================
#  CONFIGURATION
# ================================================================

DEFAULT_TARGET    = "hackathon"   # Substring match against device name
SECRET_KEY        = "hackathon2026"  # Must match firmware SECRET_KEY
COMPANY_ID        = 0x05AC        # Must match firmware COMPANY_ID
PAYLOAD_MAGIC     = 0xBE          # Must match firmware PAYLOAD_MAGIC

THRESHOLD_ROOM    = -65           # dBm — stronger than this = ROOM
THRESHOLD_NEAR    = -80           # dBm — stronger than this = NEAR, else FAR
SIGNAL_TIMEOUT    = 3.0           # seconds — no packet = NO SIGNAL

KALMAN_Q          = 0.1           # Process noise  (how fast RSSI truly changes)
KALMAN_R          = 2.0           # Measurement noise (BLE RSSI jitter)

REFRESH_HZ        = 10            # UI refresh rate
LOG_FILE          = "ble_log.csv"

# ================================================================
#  KALMAN FILTER
# ================================================================

class KalmanRSSI:
    """
    Single-variable Kalman filter for noisy RSSI smoothing.
    More adaptive than a moving average — recovers faster from
    sudden position changes while suppressing short-term noise.
    """
    def __init__(self, q: float = KALMAN_Q, r: float = KALMAN_R):
        self.q = q          # process noise covariance
        self.r = r          # measurement noise covariance
        self.x = -70.0      # initial RSSI estimate
        self.p = 1.0        # initial estimate uncertainty

    def update(self, z: float) -> float:
        # Prediction step
        self.p += self.q

        # Update step
        k     = self.p / (self.p + self.r)   # Kalman gain
        self.x += k * (z - self.x)
        self.p *= (1.0 - k)

        return self.x

    def reset(self, initial: float = -70.0):
        self.x = initial
        self.p = 1.0

# ================================================================
#  PAYLOAD VERIFICATION
# ================================================================

def verify_hmac(device_id: int, timestamp: int, received_hmac: bytes) -> bool:
    """
    Verify the 4-byte truncated HMAC from the beacon payload.
    Mirrors compute_hmac() in beacon_main.c exactly.
    """
    input_bytes = bytes([
        device_id,
        (timestamp      ) & 0xFF,
        (timestamp >>  8) & 0xFF,
        (timestamp >> 16) & 0xFF,
        (timestamp >> 24) & 0xFF,
        ])
    expected = hmac.new(
        SECRET_KEY.encode(),
        input_bytes,
        hashlib.sha256
    ).digest()[:4]

    return hmac.compare_digest(expected, received_hmac)


def parse_manufacturer_payload(mfr_data: dict) -> Optional[dict]:
    """
    Parse manufacturer-specific BLE payload from beacon_main.c.

    Expected raw bytes (after company ID stripped by Bleak):
      [0]   magic     (1 byte)
      [1]   version   (1 byte)
      [2]   device_id (1 byte)
      [3-6] timestamp (4 bytes, little-endian uint32)
      [7-10] hmac     (4 bytes)

    Returns dict with parsed fields, or None if invalid.
    """
    if COMPANY_ID not in mfr_data:
        return None

    raw = mfr_data[COMPANY_ID]
    if len(raw) < 10:
        return None

    magic, version, device_id = raw[0], raw[1], raw[2]
    if magic != PAYLOAD_MAGIC:
        return None

    timestamp = struct.unpack_from("<I", raw, 3)[0]
    rx_hmac   = bytes(raw[7:11])

    valid = verify_hmac(device_id, timestamp, rx_hmac)

    return {
        "magic":     magic,
        "version":   version,
        "device_id": device_id,
        "timestamp": timestamp,
        "hmac_ok":   valid,
    }

# ================================================================
#  BEACON STATE
# ================================================================

@dataclass
class BeaconState:
    address:    str
    name:       str
    rssi_raw:   Optional[float]  = None
    rssi_kalman: Optional[float] = None
    state:      str              = "NO SIGNAL"
    last_seen:  float            = 0.0
    packet_count: int            = 0
    hmac_ok:    Optional[bool]   = None
    device_id:  Optional[int]    = None
    kalman:     KalmanRSSI       = field(default_factory=KalmanRSSI)

    def update(self, rssi: int, payload: Optional[dict]):
        self.rssi_raw    = rssi
        self.rssi_kalman = self.kalman.update(float(rssi))
        self.last_seen   = time.time()
        self.packet_count += 1

        if payload:
            self.hmac_ok   = payload["hmac_ok"]
            self.device_id = payload["device_id"]

    def classify(self, threshold_room: int, threshold_near: int) -> str:
        if self.rssi_kalman is None:
            return "NO SIGNAL"
        if time.time() - self.last_seen > SIGNAL_TIMEOUT:
            return "NO SIGNAL"
        if self.rssi_kalman > threshold_room:
            return "ROOM"
        elif self.rssi_kalman > threshold_near:
            return "NEAR"
        else:
            return "FAR"

# ================================================================
#  MONITOR
# ================================================================

class BLEMonitor:
    def __init__(self, args):
        self.target         = args.target
        self.threshold_room = args.room
        self.threshold_near = args.near
        self.do_log         = args.log
        self.beacons: dict[str, BeaconState] = {}
        self._log_writer    = None
        self._log_file      = None
        self.console        = Console()
        self.start_time     = time.time()

    # ── Logging ──────────────────────────────────────────────

    def _init_log(self):
        self._log_file = open(LOG_FILE, "w", newline="")
        self._log_writer = csv.writer(self._log_file)
        self._log_writer.writerow([
            "timestamp", "address", "name",
            "rssi_raw", "rssi_kalman", "state",
            "device_id", "hmac_ok", "packet_count"
        ])

    def _write_log(self, b: BeaconState):
        if self._log_writer:
            self._log_writer.writerow([
                f"{time.time():.3f}",
                b.address, b.name,
                b.rssi_raw,
                f"{b.rssi_kalman:.2f}" if b.rssi_kalman else "",
                b.state,
                b.device_id,
                b.hmac_ok,
                b.packet_count,
            ])
            self._log_file.flush()

    # ── BLE Callback ─────────────────────────────────────────

    def ble_callback(self, device: BLEDevice, adv: AdvertisementData):
        name = device.name or ""
        if self.target.lower() not in name.lower():
            return
        if adv.rssi in (0, 127, None):
            return

        addr = device.address
        if addr not in self.beacons:
            self.beacons[addr] = BeaconState(address=addr, name=name or addr)

        payload = parse_manufacturer_payload(adv.manufacturer_data)
        b = self.beacons[addr]
        b.update(adv.rssi, payload)
        b.state = b.classify(self.threshold_room, self.threshold_near)

        if self.do_log:
            self._write_log(b)

    # ── UI Rendering ─────────────────────────────────────────

    def _state_markup(self, state: str) -> str:
        colors = {
            "ROOM":      "bold green",
            "NEAR":      "bold yellow",
            "FAR":       "bold red",
            "NO SIGNAL": "dim red",
        }
        c = colors.get(state, "white")
        return f"[{c}]{state}[/{c}]"

    def _hmac_markup(self, ok: Optional[bool]) -> str:
        if ok is None:
            return "[dim]-[/dim]"
        return "[green]OK[/green]" if ok else "[red]FAIL[/red]"

    def render(self) -> Panel:
        table = Table(
            box=box.ROUNDED,
            expand=True,
            show_header=True,
            header_style="bold cyan",
        )

        table.add_column("Name",        min_width=16)
        table.add_column("Addr",        min_width=18)
        table.add_column("RSSI (raw)",  justify="right", min_width=10)
        table.add_column("RSSI (filt)", justify="right", min_width=10)
        table.add_column("State",       justify="center", min_width=10)
        table.add_column("Dev ID",      justify="center", min_width=7)
        table.add_column("HMAC",        justify="center", min_width=6)
        table.add_column("Pkts",        justify="right",  min_width=6)
        table.add_column("Last seen",   justify="right",  min_width=10)

        now = time.time()

        if not self.beacons:
            table.add_row(
                f"[dim]Scanning for '{self.target}'...[/dim]",
                *[""] * 8
            )
        else:
            for b in sorted(self.beacons.values(), key=lambda x: x.name):
                age = now - b.last_seen if b.last_seen else 0
                timeout = age > SIGNAL_TIMEOUT

                rssi_raw  = f"{b.rssi_raw:.0f} dBm"  if b.rssi_raw  else "-"
                rssi_filt = f"{b.rssi_kalman:.1f} dBm" if b.rssi_kalman else "-"
                dev_id    = f"0x{b.device_id:02X}" if b.device_id is not None else "-"
                last_seen = f"{age:.1f}s ago"

                if timeout:
                    rssi_raw  = "[dim]-[/dim]"
                    rssi_filt = "[dim]-[/dim]"

                table.add_row(
                    b.name,
                    b.address,
                    rssi_raw,
                    rssi_filt,
                    self._state_markup(b.state),
                    dev_id,
                    self._hmac_markup(b.hmac_ok),
                    str(b.packet_count),
                    last_seen,
                )

        uptime   = now - self.start_time
        log_note = f"  Logging → [cyan]{LOG_FILE}[/cyan]" if self.do_log else ""
        subtitle = (
            f"Target: [cyan]{self.target}[/cyan]  |  "
            f"Thresholds: ROOM>[bold green]{self.threshold_room}[/bold green] dBm  "
            f"NEAR>[bold yellow]{self.threshold_near}[/bold yellow] dBm  |  "
            f"Uptime: {uptime:.0f}s"
            f"{log_note}"
        )

        return Panel(
            table,
            title="[bold white]BLE Beacon Monitor[/bold white]",
            subtitle=subtitle,
            border_style="bright_blue",
        )

    # ── Entry Point ──────────────────────────────────────────

    async def run(self):
        if self.do_log:
            self._init_log()
            self.console.print(f"[cyan]Logging to {LOG_FILE}[/cyan]")

        scanner = BleakScanner(self.ble_callback)
        await scanner.start()

        self.console.print(
            f"[green]Scanner started[/green] — "
            f"looking for devices containing '[cyan]{self.target}[/cyan]'\n"
            f"Press [bold]Ctrl+C[/bold] to stop."
        )
        await asyncio.sleep(1.0)

        try:
            with Live(self.render(), refresh_per_second=REFRESH_HZ,
                      console=self.console) as live:
                while True:
                    live.update(self.render())
                    await asyncio.sleep(1.0 / REFRESH_HZ)
        except KeyboardInterrupt:
            pass
        finally:
            await scanner.stop()
            if self._log_file:
                self._log_file.close()
                self.console.print(f"\n[cyan]Log saved to {LOG_FILE}[/cyan]")
            self.console.print("\n[yellow]Scanner stopped.[/yellow]")

# ================================================================
#  CLI
# ================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="BLE Beacon Monitor for presence detection system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ble_monitor.py
  python ble_monitor.py --target hackathon
  python ble_monitor.py --room -60 --near -75
  python ble_monitor.py --log
  python ble_monitor.py --target ESP32 --room -55 --near -70 --log
        """
    )
    parser.add_argument(
        "--target", default=DEFAULT_TARGET,
        help=f"Device name substring to scan for (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--room", type=int, default=THRESHOLD_ROOM,
        help=f"RSSI threshold for ROOM classification in dBm (default: {THRESHOLD_ROOM})"
    )
    parser.add_argument(
        "--near", type=int, default=THRESHOLD_NEAR,
        help=f"RSSI threshold for NEAR classification in dBm (default: {THRESHOLD_NEAR})"
    )
    parser.add_argument(
        "--log", action="store_true",
        help=f"Enable CSV logging to {LOG_FILE}"
    )
    return parser.parse_args()


def main():
    # Windows requires a specific event loop policy for BLE
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    args = parse_args()
    monitor = BLEMonitor(args)

    try:
        asyncio.run(monitor.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()