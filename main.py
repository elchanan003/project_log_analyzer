from reader import read_logs_with_yield
from config import LOG_PATH, suspicion_checks
from checks import filter_suspicious_rows, add_suspicion_details, count_items


def main():
    lines = read_logs_with_yield(LOG_PATH)
    suspicious = filter_suspicious_rows(lines, suspicion_checks)
    detailed = add_suspicion_details(suspicious, suspicion_checks)

    count = count_items(detailed)

    print(f"Total suspicious: {count}")


if __name__ == "__main__":
    main()