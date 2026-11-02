import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logprocessor import find_arp_poisoning, find_packet_floods


def packet(time, source, destination, protocol, info, dest_port=""):
    return {
        "time": time,
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "info": info,
        "destPort": dest_port,
    }


def arp_reply(time, mac, ip):
    return packet(time, mac, "ff:ff:ff:ff:ff:ff", "ARP", f"{ip} is at {mac}")


def syn(time, host, port, flags="[SYN]"):
    return packet(time, host, host, "TCP", f"{port} → {port} {flags} Seq=0 Win=512 Len=0")


class ArpPoisoningTests(unittest.TestCase):
    def test_one_mac_claiming_several_addresses_is_flagged(self):
        packets = [
            arp_reply("2026-03-14 09:13:10", "08:00:2b:ef:ab:7c", "192.168.1.1"),
            arp_reply("2026-03-14 09:13:11", "08:00:2b:ef:ab:7c", "192.168.1.20"),
            arp_reply("2026-03-14 09:13:12", "08:00:2b:ef:ab:7c", "192.168.1.35"),
        ]
        self.assertEqual(find_arp_poisoning(packets), [{
            "type": "ARP Poisoning Attack",
            "info": "08:00:2b:ef:ab:7c",
            "count": "3 attacks",
            "time": "2026-03-14 09:13:10",
        }])

    def test_repeated_replies_for_one_address_are_normal(self):
        packets = [arp_reply(f"2026-03-14 09:00:0{n}", "00:0c:29:aa:10:01", "192.168.1.1") for n in range(5)]
        self.assertEqual(find_arp_poisoning(packets), [])

    def test_claims_on_different_days_are_not_combined(self):
        packets = [
            arp_reply("2026-03-14 23:59:59", "08:00:2b:ef:ab:7c", "192.168.1.1"),
            arp_reply("2026-03-15 00:00:01", "08:00:2b:ef:ab:7c", "192.168.1.20"),
        ]
        self.assertEqual(find_arp_poisoning(packets), [])

    def test_each_attacking_mac_gets_its_own_row(self):
        packets = [
            arp_reply("2026-03-14 09:00:00", "aa:aa:aa:aa:aa:aa", "10.0.0.1"),
            arp_reply("2026-03-14 09:00:01", "aa:aa:aa:aa:aa:aa", "10.0.0.2"),
            arp_reply("2026-03-14 09:00:02", "bb:bb:bb:bb:bb:bb", "10.0.0.1"),
            arp_reply("2026-03-14 09:00:03", "bb:bb:bb:bb:bb:bb", "10.0.0.3"),
        ]
        self.assertEqual([row["info"] for row in find_arp_poisoning(packets)], ["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"])

    def test_only_arp_packets_are_checked(self):
        packets = [
            arp_reply("2026-03-14 09:00:00", "aa:aa:aa:aa:aa:aa", "10.0.0.1"),
            packet("2026-03-14 09:00:01", "aa:aa:aa:aa:aa:aa", "10.0.0.9", "TCP", "Data for 10.0.0.2"),
        ]
        self.assertEqual(find_arp_poisoning(packets), [])

    def test_protocol_name_is_not_case_sensitive(self):
        packets = [
            packet("2026-03-14 09:00:00", "aa:aa:aa:aa:aa:aa", "ff:ff:ff:ff:ff:ff", "arp", "10.0.0.1 is at aa:aa:aa:aa:aa:aa"),
            packet("2026-03-14 09:00:01", "aa:aa:aa:aa:aa:aa", "ff:ff:ff:ff:ff:ff", "arp", "10.0.0.2 is at aa:aa:aa:aa:aa:aa"),
        ]
        self.assertEqual(len(find_arp_poisoning(packets)), 1)


class PacketFloodTests(unittest.TestCase):
    def test_counts_packets_per_port_per_day(self):
        packets = [
            syn("2026-03-14 10:40:00", "192.168.1.10", 80),
            syn("2026-03-14 10:40:01", "192.168.1.10", 80),
            syn("2026-03-14 10:40:02", "192.168.1.10", 80),
            syn("2026-03-14 11:00:00", "192.168.1.10", 443),
            syn("2026-03-15 08:05:41", "192.168.1.10", 80),
        ]
        self.assertCountEqual(find_packet_floods(packets), [
            {"type": "Packet Flood", "info": "Packet Flag: [SYN]", "count": "Port: 80 Attacks: 3", "time": "2026-03-14 10:40:00"},
            {"type": "Packet Flood", "info": "Packet Flag: [SYN]", "count": "Port: 443 Attacks: 1", "time": "2026-03-14 11:00:00"},
            {"type": "Packet Flood", "info": "Packet Flag: [SYN]", "count": "Port: 80 Attacks: 1", "time": "2026-03-15 08:05:41"},
        ])

    def test_syn_ack_replies_are_not_counted(self):
        packets = [syn("2026-05-02 14:21:31", "10.0.0.40", 443, flags="[SYN, ACK]")]
        self.assertEqual(find_packet_floods(packets), [])

    def test_normal_connections_between_hosts_are_ignored(self):
        packets = [packet("2026-03-14 09:12:05", "192.168.1.20", "93.184.216.34", "TCP", "51522 → 443 [SYN] Seq=0")]
        self.assertEqual(find_packet_floods(packets), [])

    def test_destination_port_column_is_used_when_info_has_no_port(self):
        packets = [
            packet("2026-05-02 14:21:30", "10.0.0.40", "10.0.0.40", "TCP", "[SYN] Seq=0", dest_port="8443"),
            packet("2026-05-02 14:21:31", "10.0.0.40", "10.0.0.40", "TCP", "[SYN] Seq=0", dest_port="8443"),
        ]
        self.assertEqual(find_packet_floods(packets)[0]["count"], "Port: 8443 Attacks: 2")

    def test_other_flags_can_be_checked(self):
        packets = [
            syn("2026-03-14 10:40:00", "192.168.1.10", 22, flags="[RST]"),
            syn("2026-03-14 10:40:01", "192.168.1.10", 22, flags="[SYN]"),
        ]
        self.assertEqual(find_packet_floods(packets, flag="[RST]"), [
            {"type": "Packet Flood", "info": "Packet Flag: [RST]", "count": "Port: 22 Attacks: 1", "time": "2026-03-14 10:40:00"},
        ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
