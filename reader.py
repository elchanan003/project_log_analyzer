from pathlib import Path

HERE = Path(__file__).resolve().parent
log_path = HERE / 'network_traffic.log'


def get_log(path):
    """
    הפונקציה מקבלת נתיב לקובץ log
    ומחזירה רשימה של רשימות - כל שורה כרשימה של שדות
    :param path:
    :return list:
    """
    with open(path, 'r') as f:
        return [line.strip().split(',') for line in f]
