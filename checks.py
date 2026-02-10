from reader import get_log

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
