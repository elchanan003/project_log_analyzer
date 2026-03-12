from analyzer import analyze_log
from reporter import generate_report, save_report


def main():

    suspicious = analyze_log("network_traffic.log")

    report = generate_report(suspicious)

    print(report)

    save_report(report, "security_report.txt")


if __name__ == "__main__":
    main()