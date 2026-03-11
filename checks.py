from collections import Counter
from config import SENSITIVE_PORTS, LARGE_PACKET_THRESHOLD, NIGHT_START_HOUR, NIGHT_END_HOUR


def filter_external_ips(logs):
    """
    הפונקציה מקבלת את הנתונים
    ומחזירה רשימה של כתובות IP מקור
    חיצוניות בלבד
    :param logs:
    :return list:
    """
    return [
        row[1]
        for row in logs
        if not row[1].startswith("192.168") and not row[1].startswith("10.")
    ]


def filter_sensitive_ports(logs):
    """
    הפונקציה מקבלת את הנתונים
    ומחזירה רשימה של כל השורות עם פורט רגיש
    :param logs:
    :return list:
    """
    return list(filter(lambda row: row[3] in SENSITIVE_PORTS, logs))


def filter_large_sizes(logs):
    """
    הפונקציה מקבלת את הנתונים ומחזירה רשימה
    של כל השורות עם חבילות מעל 5000 בייט
    :param logs:
    :return list:
    """
    return [row for row in logs if float(row[5]) > LARGE_PACKET_THRESHOLD]


def add_label_sizes(logs):
    """
    הפונקציה מקבלת את הנתונים
    ומחזירה רשימה שבה כל שורה מתויגת
    כ'גדול' או 'נורמלי' לפי חריגה מ 5000 בייטים
    :param logs:
    :return list:
    """
    return [
        row + ["LARGE"] if float(row[5]) > LARGE_PACKET_THRESHOLD else row + ["NORMAL"]
        for row in logs
    ]


def count_source_ips(logs):
    """
    כתבו פונקציה שמקבלת את הנתונים ומחזירה מילון:
    כתובת IP מקור → מספר הפניות שלה
    :param logs:
    :return dict:
    """
    return {
        source_ip: count
        for source_ip, count in Counter(row[1] for row in logs).items()
    }


def get_port_protocol_dict(logs):
    """
    הפונקציה מקבלת את הנתונים ומחזירה מילון:
    מספר פורט - שם הפרוטוקול
    :param logs:
    :return dict:
    """
    return {row[3]: row[4] for row in logs}


def get_hours(logs):
    """
    פונקציה שמקבלת את הנתונים,
    ומחזירה רשימה של השעות בלבד מכל השורות
    :param logs:
    :return list:
    """
    return list(map(lambda row: int(row[0][11:13]), logs))


def convert_bytes_to_kb(logs):
    """
    ממירה גודל קבצים מבייטים לקילו בייטים
    :param logs:
    :return:
    """
    return list(map(lambda row: round(int(row[5]) / 1024, 2), logs))


def night_activity_by_filter(logs):
    """
    סינון לוגים עם פעילות לילה
    באמצעות שימוש בפונקצית פילטר
    :param logs:
    :return:
    """
    return list(
        filter(
            lambda row: NIGHT_START_HOUR <= int(row[0][11:13]) < NIGHT_END_HOUR,
            logs
        )
    )

def check_row_suspicions(row, suspicion_checks):
    """
    הפונקציה מקבלת שורה אחת מהלוג ומילון בדיקות חשד,
    ומחזירה רשימה של שמות החשדות שמתקיימים עבור השורה.

    :param row: שורת לוג בודדת
    :type row: list
    :param suspicion_checks: מילון שבו המפתח הוא שם החשד
    והערך הוא פונקציה שבודקת אם השורה עומדת בקריטריון
    :type suspicion_checks: dict
    :return: רשימת שמות החשדות שהשורה עומדת בהם
    :rtype: list
    """
    return [item[0] for item in filter(lambda item: item[1](row), suspicion_checks.items())]


def check_log(logs, suspicion_checks):
    """
    הפונקציה מקבלת את כל שורות הלוג ומילון בדיקות חשד,
    ומחזירה רשימה של זוגות:
    (שורת לוג, רשימת החשדות שלה)

    רק שורות שיש להן לפחות חשד אחד יוחזרו.

    :param logs: רשימת שורות הלוג
    :type logs: list
    :param suspicion_checks: מילון בדיקות חשד
    :type suspicion_checks: dict
    :return: רשימה של זוגות (row, suspicions)
    :rtype: list
    """
    return list(
        filter(
            lambda item: item[1],
            map(lambda row: (row, check_row_suspicions(row, suspicion_checks)), logs)
        )
    )



