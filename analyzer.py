from reader import get_log, read_logs_with_yield
from checks import (
    filter_large_sizes,
    filter_external_ips,
    filter_sensitive_ports,
    night_activity_by_filter,
    add_suspicion_details
)
from config import (
    EXTERNAL_IP_LABEL,
    SENSITIVE_PORT_LABEL,
    LARGE_PACKET_LABEL,
    NIGHT_ACTIVITY_LABEL,
    suspicion_checks
)


TOTAL_LINES = 0
SUSPICIOUS_LINES = 0
SUSPICION_COUNTER = {
    EXTERNAL_IP_LABEL: 0,
    SENSITIVE_PORT_LABEL: 0,
    LARGE_PACKET_LABEL: 0,
    NIGHT_ACTIVITY_LABEL: 0
}

def update_statistics(labels):
    """
    מעדכנת את הסטטיסטיקות הגלובליות עבור שורה אחת.

    :param labels: רשימת החשדות שנמצאו בשורה
    :type labels: list
    """
    global TOTAL_LINES
    global SUSPICIOUS_LINES
    global SUSPICION_COUNTER

    TOTAL_LINES += 1

    if labels:
        SUSPICIOUS_LINES += 1

        for label in labels:
            SUSPICION_COUNTER[label] += 1


def analyze_log(path):
    """
    מנתחת קובץ לוג ומחזירה מילון של כתובות IP חשודות.

    הפונקציה קוראת את הלוג באמצעות generator, מזהה חשדות עבור כל שורה,
    מעדכנת סטטיסטיקות גלובליות, ובונה מילון שבו כל IP משויך לרשימת
    החשדות שהתגלו עבורו.

    :param path: נתיב לקובץ הלוג
    :type path: str | Path
    :return: מילון שבו המפתח הוא כתובת IP והערך הוא רשימת החשדות שלה
    :rtype: dict
    """

    suspicious_dict = {}

    logs = read_logs_with_yield(path)

    for row, labels in add_suspicion_details(logs, suspicion_checks):
        update_statistics(labels)

        ip = row[1]

        if ip not in suspicious_dict:
            suspicious_dict[ip] = set(labels)
        else:
            suspicious_dict[ip].update(labels)

    for ip in suspicious_dict:
        suspicious_dict[ip] = list(suspicious_dict[ip])

    return suspicious_dict


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
