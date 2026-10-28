
from datetime import datetime, timezone

CHECKS = {"tls": "TLS certificate", "dns-auth": "Email authentication", "headers": "Browser security headers"}


def _symbol(level):
    return {"ok": "PASS", "warn": "WARN", "fail": "FAIL"}.get(level, level.upper())


def render(target, scope, results):
    lines = []
    lines.append("# Exposure assessment: %s" % target)
    lines.append("")
    lines.append("Generated %s" % datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    lines.append("")
    lines.append("Authorisation reference: %s" % scope.get("authorisation_reference", ""))
    lines.append("")
    lines.append("| Check | Grade |")
    lines.append("|-------|-------|")
    for item in results:
        lines.append("| %s | %s |" % (CHECKS.get(item["check"], item["check"]), item["grade"]))
    lines.append("")
    for item in results:
        lines.append("## %s: grade %s" % (CHECKS.get(item["check"], item["check"]), item["grade"]))
        lines.append("")
        for level, text in item["findings"]:
            lines.append("- **%s** %s" % (_symbol(level), text))
        lines.append("")
        lines.append("Remediation: %s" % item["remediation"])
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Read only checks, run against targets named in the scope file.")
    return chr(10).join(lines) + chr(10)
