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