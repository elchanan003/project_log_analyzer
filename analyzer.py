from reader import get_log
from checks import filter_external_ips, filter_sensitive_ports, add_label_sizes

def get_ip_labels(path):
    """
    הפונקציה מקבלת את הנתונים ומחזירה מילון
    {כתובת ip : רשמת סוגי החשדות}
    :param path:
    :return dict:
    """
    external_ips = set(filter_external_ips(path))
    sensitive_ports_ips = set([ip[1] for ip in filter_sensitive_ports(path)])
    large_packet_ips = set([ip[1] for ip in add_label_sizes(path) if ip[-1] == "LARGE"])
    night_activity_ips = set([ip[1] for ip in get_log(path) if 6 > int(ip[0][11:13]) >= 0])

    criteria_labels = [
        ("IP_EXTERNAL", external_ips),
        ("PORT_SENSITIVE", sensitive_ports_ips),
        ("PACKET_LARGE", large_packet_ips),
        ("ACTIVITY_NIGHT", night_activity_ips)
    ]

    return {ip[1]:[label for label, group in criteria_labels if ip[1] in group]
            for ip in get_log(path)}

def filter_suspicious_ips(path):
    """
    הפונקציה מקבלת את מילון החשדות ומחזירה מילון חדש
    רק עם כתובות שיש להן לפחות 2 חשדות
    :param path:
    :return dict:
    """
    ip_labels = get_ip_labels(path)
    return {ip:labels for ip, labels in ip_labels.items() if len(labels) >= 2}