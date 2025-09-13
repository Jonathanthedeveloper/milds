"""Network monitoring helpers (wrapper around scapy-based logic).

This module exposes `network_monitor(cfg, logger, interface=None)` which
keeps the original detection logic but accepts a Config and logger.
"""
from typing import Optional
import time
from .config import Config
import scapy.all as scapy
import numpy as np
from .events import EventDispatcher


def network_monitor(cfg: Config, logger, interface: Optional[str] = None, dispatcher: Optional[EventDispatcher] = None):
    # Respect configuration toggle
    if not getattr(cfg, 'enable_network', False):
        logger.info('Network monitoring disabled by configuration')
        return

    # Ensure scapy is usable
    if not getattr(scapy, 'sniff', None):
        logger.info('Network monitoring disabled: scapy sniff not available')
        return

    try:
        # quick sniff test with no store to verify capture is available
        scapy.sniff(count=0, timeout=1)
    except Exception as e:
        logger.info('Packet capture not available', extra={'extra': {'error': str(e)}})
        return

    logger.info('Network monitor started', extra={'extra': {'interface': interface}})

    # Internal detector state
    connections: dict[str, list[int]] = {}
    packet_times: list[float] = []
    packet_sizes: list[int] = []
    seen_ssids: set[str] = set()

    def handle_packet(packet) -> None:
        try:
            current_time = time.time()
            src_ip = None
            packet_size = len(packet)

            # WiFi beacon / rogue AP
            if getattr(packet, 'haslayer', None) and packet.haslayer(scapy.Dot11Beacon):  # type: ignore
                try:
                    ssid = packet[scapy.Dot11Beacon].info.decode('utf-8', errors='ignore')  # type: ignore
                    if ssid and ssid not in seen_ssids:
                        seen_ssids.add(ssid)
                        if len(seen_ssids) > 10:
                            logger.info('Rogue AP detected', extra={'extra': {'ssid': ssid}})
                            if dispatcher:
                                dispatcher.emit('Rogue AP', {'ssid': ssid})
                except Exception:
                    pass

            if getattr(packet, 'haslayer', None) and packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):  # type: ignore
                src_ip = packet[scapy.IP].src  # type: ignore
                dst_port = packet[scapy.TCP].dport  # type: ignore
                flags = packet[scapy.TCP].flags  # type: ignore
                if src_ip not in connections:
                    connections[src_ip] = []
                if flags & 0x02:  # SYN
                    connections[src_ip].append(dst_port)
                    if len(set(connections[src_ip])) > cfg.port_scan_threshold:
                        logger.info('Port Scan', extra={'extra': {'src': src_ip}})
                        if dispatcher:
                            dispatcher.emit('Port Scan', {'ip': src_ip})
                        connections[src_ip] = []

            # DoS detection: packet rate per second
            packet_times.append(current_time)
            # keep only recent 1s window
            packet_times[:] = [t for t in packet_times if current_time - t < 1]
            if len(packet_times) > cfg.packet_rate_threshold:
                logger.info('Possible DoS', extra={'extra': {'rate': len(packet_times), 'src': src_ip}})
                if dispatcher:
                    dispatcher.emit('Possible DoS', {'rate': len(packet_times), 'ip': src_ip})

            # MAD anomaly on packet sizes
            packet_sizes.append(packet_size)
            packet_sizes[:] = packet_sizes[-100:]
            if len(packet_sizes) > 5:
                median = np.median(packet_sizes)
                mad = np.median([abs(s - median) for s in packet_sizes])
                if mad > 0 and abs(packet_size - median) / mad > 3.5:
                    logger.info('Anomaly', extra={'extra': {'size': packet_size, 'src': src_ip}})
                    if dispatcher:
                        dispatcher.emit('Anomaly', {'size': packet_size, 'ip': src_ip})

        except Exception as e:
            # Do not raise from packet handler; just log
            logger.debug('Packet handler error', extra={'extra': {'error': str(e)}})

    # Attempt to run sniffing in a safe, repeated short-capture loop so the function
    # can be stopped by the surrounding program (threads are daemonized in index.py)
    try:
        # Auto-detect interface if not supplied
        if interface is None:
            try:
                interfaces = scapy.get_working_ifaces()  # type: ignore
                interface = next((i.name for i in interfaces if 'wlan' in i.name.lower() or 'wi-fi' in i.name.lower()), None)
                interface = interface or interfaces[0].name
            except Exception:
                interface = None

        # Run repeated short sniffs
        while True:
            try:
                scapy.sniff(iface=interface, prn=handle_packet, store=False, timeout=2)  # type: ignore
            except TypeError:
                # some scapy builds don't accept timeout when store=False on Windows
                scapy.sniff(iface=interface, prn=handle_packet, store=False)  # type: ignore
            # small sleep to yield
            time.sleep(0.1)
    except KeyboardInterrupt:
        logger.info('Network monitor stopped by KeyboardInterrupt')
    except Exception as e:
        logger.info('Network monitoring stopped', extra={'extra': {'error': str(e)}})
    return
