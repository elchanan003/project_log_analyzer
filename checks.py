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
