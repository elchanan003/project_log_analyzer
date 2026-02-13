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

def get_hours(path):
    """
    פונקציה שמקבלת את הנתונים,
    ומחזירה רשימה של השעות בלבד מכל השורות
    :param path:
    :return list:
    """
    return list(map(lambda data_time: int(data_time[0][11:13]) ,get_log(path)))

def convert_bytes_to_kb(path):
    """
    ממירה גודל קבצים מבייטים לקילו בייטים
    :param path:
    :return:
    """
    return list(map(lambda row: round(int(row[5]) / 1024, 2), get_log(path)))

def filter_sensitive_ports_v2(path):
    """
    סינון שורות עם פורט רגיש
    ע״י שימוש בפונקציית פילטר
    :param path:
    :return:
    """
    return filter(lambda row: row[4] in ('22', '23', '3389'), get_log(path))