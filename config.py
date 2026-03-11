import ipaddress
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOG_PATH = HERE / "network_traffic.log"

SENSITIVE_PORTS = ("22", "23", "3389")
LARGE_PACKET_THRESHOLD = 5000
NIGHT_START_HOUR = 0
NIGHT_END_HOUR = 6

EXTERNAL_IP_LABEL = "EXTERNAL_IP"
SENSITIVE_PORT_LABEL = "SENSITIVE_PORT"
LARGE_PACKET_LABEL = "LARGE_PACKET"
NIGHT_ACTIVITY_LABEL = "NIGHT_ACTIVITY"

suspicion_checks = {
"EXTERNAL_IP": lambda row: not row[1].startswith("192.168") and not row[1].startswith("10."),
"SENSITIVE_PORT": lambda row: row[3] in SENSITIVE_PORTS,
"LARGE_PACKET": lambda row: float(row[5]) > LARGE_PACKET_THRESHOLD,
"NIGHT_ACTIVITY": lambda row: NIGHT_START_HOUR <= int(row[0][11:13]) < NIGHT_END_HOUR,
}