from analyzer import TOTAL_LINES, SUSPICIOUS_LINES, SUSPICION_COUNTER


def generate_report(suspicious_dict):
    """
    מייצרת דוח טקסטואלי של פעילות חשודה ברשת.

    הדוח כולל סטטיסטיקות כלליות ורשימת כתובות IP
    עם החשדות שהתגלו עבורן.

    :param suspicious_dict: מילון IP → רשימת חשדות
    :type suspicious_dict: dict
    :return: מחרוזת הדוח המלא
    :rtype: str
    """

    report = []

    report.append("====================================")
    report.append("דוח תעבורה חשודה")
    report.append("====================================")

    report.append("סטטיסטיקות כלליות:")
    report.append(f"שורות שנקראו: {TOTAL_LINES}")
    report.append(f"שורות חשודות: {SUSPICIOUS_LINES}")

    for suspicion, count in SUSPICION_COUNTER.items():
        report.append(f"{suspicion}: {count}")

    report.append("")
    report.append("IPs עם רמת סיכון גבוהה (+3 חשדות):")

    for ip, labels in suspicious_dict.items():
        if len(labels) >= 3:
            report.append(f"{ip}: {', '.join(labels)}")

    report.append("")
    report.append("IPs חשודים נוספים:")

    for ip, labels in suspicious_dict.items():
        if len(labels) < 3:
            report.append(f"{ip}: {', '.join(labels)}")

    return "\n".join(report)


def save_report(report, filepath):
    """
    שומר את דוח האבטחה לקובץ טקסט.

    :param report: מחרוזת הדוח
    :type report: str
    :param filepath: נתיב לקובץ הפלט
    :type filepath: str
    """
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report)
