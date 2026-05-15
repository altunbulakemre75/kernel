"""Live WiFi/BT RF listener — scapy + bleak based (stub).

Hardware requirements:
  - WiFi NAN: monitor-mode WiFi adapter (e.g. Alfa AWUS036ACS)
    + Linux iwconfig monitor-mode
  - Bluetooth LE: BT 4.0+ chipset + bleak library

Monitor mode is generally not supported on Windows — Linux recommended.
This module is imported with optional imports: if scapy/bleak are not
installed, the service falls back to mock mode.
"""
from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator

log = logging.getLogger(__name__)


def check_scapy_available() -> bool:
    try:
        import scapy.all  # noqa: PLC0415, F401
        return True
    except ImportError:
        return False


def check_bleak_available() -> bool:
    try:
        import bleak  # noqa: PLC0415, F401
        return True
    except ImportError:
        return False


async def sniff_wifi_probe_requests(iface: str) -> AsyncIterator[tuple[str, int | None, int | None]]:
    """Capture WiFi probe request frames from a monitor-mode interface.

    Yields: (mac, rssi, channel)
    """
    try:
        from scapy.all import sniff, Dot11, RadioTap, Dot11ProbeReq  # noqa: PLC0415
    except ImportError:
        log.error("scapy not installed — pip install scapy")
        return

    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    loop = asyncio.get_event_loop()

    def _on_packet(pkt):
        if not pkt.haslayer(Dot11ProbeReq):
            return
        mac = pkt.addr2
        rssi = None
        channel = None
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            rssi = getattr(rt, "dBm_AntSignal", None)
            channel = getattr(rt, "Channel", None)
        loop.call_soon_threadsafe(queue.put_nowait, (mac, rssi, channel))

    log.info("WiFi sniff starting: iface=%s", iface)

    def _sniff_thread():
        sniff(iface=iface, prn=_on_packet, store=0)

    import threading
    threading.Thread(target=_sniff_thread, daemon=True).start()

    while True:
        mac, rssi, channel = await queue.get()
        yield mac, rssi, channel


async def scan_ble_advertisements() -> AsyncIterator[tuple[str, int | None, bytes]]:
    """BLE scanner — suitable for ODID broadcasts.

    Yields: (mac, rssi, raw_data)
    """
    try:
        from bleak import BleakScanner  # noqa: PLC0415
    except ImportError:
        log.error("bleak not installed — pip install bleak")
        return

    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    def _on_detection(device, adv_data):
        raw = bytes(adv_data.manufacturer_data.get(0x090D, b""))  # ASTM CID
        queue.put_nowait((device.address, adv_data.rssi, raw))

    scanner = BleakScanner(detection_callback=_on_detection)
    await scanner.start()
    log.info("BLE scan started")

    try:
        while True:
            mac, rssi, raw = await queue.get()
            yield mac, rssi, raw
    finally:
        await scanner.stop()
