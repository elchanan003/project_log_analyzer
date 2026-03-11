from reader import get_log
from checks import (
    filter_large_sizes,
    filter_external_ips,
    filter_sensitive_ports,
    night_activity_by_filter
)
from config import (
    EXTERNAL_IP_LABEL,
    SENSITIVE_PORT_LABEL,
    LARGE_PACKET_LABEL,
    NIGHT_ACTIVITY_LABEL,
    suspicion_checks
)

def get_ip_labels(path):
    """
    הפונקציה מקבלת את הנתונים ומחזירה מילון
    {כתובת ip : רשימת סוגי החשדות}
    :param path:
    :return dict:
    """
    logs = get_log(path)

    external_ips = set(filter_external_ips(logs))
    sensitive_ports_ips = {row[1] for row in filter_sensitive_ports(logs)}
    large_packet_ips = {row[1] for row in filter_large_sizes(logs)}
    night_activity_ips = {row[1] for row in night_activity_by_filter(logs)}

    criteria_labels = [
        (EXTERNAL_IP_LABEL, external_ips),
        (SENSITIVE_PORT_LABEL, sensitive_ports_ips),
        (LARGE_PACKET_LABEL, large_packet_ips),
        (NIGHT_ACTIVITY_LABEL, night_activity_ips)
    ]

    return {
        row[1]: [label for label, group in criteria_labels if row[1] in group]
        for row in logs
    }


def filter_suspicious_ips(path):
    """
    הפונקציה מקבלת את מילון החשדות ומחזירה מילון חדש
    רק עם כתובות שיש להן לפחות 2 חשדות
    :param path:
    :return dict:
    """
    ip_labels = get_ip_labels(path)
    return {ip: labels for ip, labels in ip_labels.items() if len(labels) >= 2}
