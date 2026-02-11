from reader import get_log, log_path
from collections import Counter

def filter_external_ips(path):
    """
    הפונקציה מקבלת את הנתונים
    ומחזירה רשימה של כתובות IP מקור
    חיצוניות בלבד
    :param path:
    :return list:
    """
    return [ip_address[1] for ip_address in get_log(path) if ip_address[1][:2] != '10' and ip_address[1][:7] != '192.168']

def filter_sensitive_ports(path):
    """
    הפונקציה מקבלת את הנתונים
    ומחזירה רשימה של כל השורות עם פורט רגיש
    :param path:
    :return list:
    """
    return [ip_address for ip_address in get_log(path) if ip_address[3] in ('22', '23', '3389')]

def filter_large_sizes(path):
    """
     הפונקציה מקבלת את הנתונים ומחזירה רשימה
     של כל השורות עם חבילות מעל 5000 בייט
    :param path:
    :return list:
    """
    return [ip_address for ip_address in get_log(path) if float(ip_address[-1]) > 5000]

def add_label_sizes(path):
    """
    הפונקציה מקבלת את הנתונים
    ומחזירה רשימה שבה כל שורה מתויגת
    כ'גדול' או 'נורמלי' לפי חריגה מ 5000 בייטים
    :param path:
    :return list:
    """
    return [item + ["LARGE"] if float(item[-1]) > 5000 else item + ["NORMAL"] for item in get_log(path)]


def count_source_ips(path):
    """
    כתבו פונקציה שמקבלת את הנתונים ומחזירה מילון:
    כתובת IP מקור → מספר הפניות שלה
    :param path:
    :return dict:
    """
    return {ip_source:count for ip_source, count in Counter(ip_address[1] for ip_address in get_log(path)).items()}

def get_port_protocol_dict(path):
    """
    הפונקציה מקבלת את הנתונים ומחזירה מילון:
    מספר פורט - שם הפרוטוקול
    :param path:
    :return dict:
    """
    return {ip_address[3]:ip_address[4] for ip_address in get_log(path)}

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

    return {ip[1]:[label for (label, group) in criteria_labels if ip[1] in group]
            for ip in get_log(path)}

def filter_suspicious_ips(path):
    """
    הפונקציה מקבלת את מילון החשדות ומחזירה מילון חדש
     רק עם כתובות שיש להן לפחות 2 חשדות
    :param path:
    :return:
    """
    ip_labels = get_ip_labels(path)
    return {ip:labels for ip, labels in ip_labels.items() if len(labels) >= 2}