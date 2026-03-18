import datetime


def generate_report(input_file, ips, domains, vt_results):

    report = []

    report.append("=== SOC INVESTIGATION REPORT ===\n")

    report.append(f"Source file: {input_file}")
    report.append(f"Analysis time: {datetime.datetime.now()}\n")

    report.append(f"Total IPs observed: {len(ips)}")
    report.append(f"Total domains observed: {len(domains)}\n")

    report.append("Threat Intelligence Results:\n")

    for r in vt_results:

        vt = r["vt"]

        report.append(
            f"{r['ioc']} | malicious: {vt['malicious']} "
            f"suspicious: {vt['suspicious']} harmless: {vt['harmless']}"
        )

    report.append("\nRecommended action:")

    suspicious = [r for r in vt_results if r["vt"]["malicious"] > 0]

    if suspicious:
        report.append("Investigate hosts communicating with malicious infrastructure.")
    else:
        report.append("No confirmed malicious IoCs detected.")


    report_text = "\n".join(report)

    return report_text