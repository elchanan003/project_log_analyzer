def get_log(path):
    """
    הפונקציה מקבלת נתיב לקובץ log
    ומחזירה רשימה של רשימות - כל שורה כרשימה של שדות
    :param path: נתיב לקובץ הלוג
    :type path: str | Path
    :return: רשימת שורות, כאשר כל שורה היא רשימת שדות
    :rtype: list
    """
    with open(path, 'r', encoding='utf-8') as f:
        return [line.strip().split(',') for line in f]

def read_logs_with_yield(path):
    """
    קורא קובץ לוג ומחזיר generator של שורות.

    כל שורה מוחזרת כרשימת שדות.

    :param path: נתיב לקובץ הלוג
    :type path: str | Path
    :yield: שורת לוג כרשימת שדות
    :rtype: list
    """
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            yield line.strip().split(',')