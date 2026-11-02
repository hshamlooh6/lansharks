import csv
import os
import re
from datetime import datetime

from common import LOGS_DIR, db

IP_ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_AND_FLAG = re.compile(r"(\d+)\s*(\[[A-Z, ]+\])")

COLUMNS = {
    "packetNo": ("no", "number", "packet"),
    "time": ("time", "datetime", "date", "timestamp"),
    "source": ("source", "src", "sourceip", "srcip", "sourcemac"),
    "destination": ("destination", "dst", "destip", "destinationip"),
    "protocol": ("protocol", "proto"),
    "length": ("length", "len"),
    "info": ("info", "information"),
    "destPort": ("destport", "dstport", "destinationport"),
}


def normalize(header):
    return re.sub(r"[^a-z0-9]", "", header.lower())


def read_packets(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        lookup = {normalize(name): name for name in reader.fieldnames or []}
        columns = {
            field: next((lookup[alias] for alias in aliases if alias in lookup), None)
            for field, aliases in COLUMNS.items()
        }
        return [
            {field: (row.get(column) or "").strip() if column else "" for field, column in columns.items()}
            for row in reader
        ]


def import_logs():
    if not os.path.isdir(LOGS_DIR):
        return
    for name in sorted(os.listdir(LOGS_DIR)):
        stem, extension = os.path.splitext(name)
        prefix = stem.split("_", 1)[0]
        if extension.lower() != ".csv" or not prefix.isdigit():
            continue

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        processed = os.path.join(LOGS_DIR, f"{stem}_{stamp}.old")
        try:
            os.rename(os.path.join(LOGS_DIR, name), processed)
            packets = read_packets(processed)
        except (OSError, UnicodeDecodeError, csv.Error):
            continue

        with db() as conn:
            conn.executemany(
                """INSERT INTO incidents
                   (customerNumber, packetNo, time, source, destination, protocol, length, info, destPort, sourceFile)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (int(prefix), p["packetNo"], p["time"], p["source"], p["destination"],
                     p["protocol"], p["length"], p["info"], p["destPort"], name)
                    for p in packets
                ],
            )


def find_arp_poisoning(packets):
    groups = {}
    for packet in packets:
        if packet["protocol"].upper() != "ARP":
            continue
        addresses = IP_ADDRESS.findall(packet["info"])
        if not addresses:
            continue
        key = (packet["source"], packet["time"][:10])
        group = groups.setdefault(key, {"ips": set(), "packets": 0, "first": packet["time"]})
        group["ips"].add(addresses[-1])
        group["packets"] += 1

    return [
        {"type": "ARP Poisoning Attack", "info": mac, "count": f"{group['packets']} attacks", "time": group["first"]}
        for (mac, _), group in groups.items()
        if len(group["ips"]) > 1
    ]


def find_packet_floods(packets, flag="[SYN]"):
    groups = {}
    for packet in packets:
        if flag not in packet["info"] or not packet["source"] or packet["source"] != packet["destination"]:
            continue
        ports = {tag: number for number, tag in PORT_AND_FLAG.findall(packet["info"])}
        port = ports.get(flag) or packet["destPort"] or "unknown"
        key = (port, packet["time"][:10])
        group = groups.setdefault(key, {"packets": 0, "first": packet["time"]})
        group["packets"] += 1

    return [
        {
            "type": "Packet Flood",
            "info": f"Packet Flag: {flag}",
            "count": f"Port: {port} Attacks: {group['packets']}",
            "time": group["first"],
        }
        for (port, _), group in groups.items()
    ]


def detect_attacks(customer_number):
    with db() as conn:
        packets = conn.execute(
            "SELECT * FROM incidents WHERE customerNumber = ? ORDER BY time, id",
            (customer_number,),
        ).fetchall()
    attacks = find_arp_poisoning(packets) + find_packet_floods(packets)
    return sorted(attacks, key=lambda attack: attack["time"])
