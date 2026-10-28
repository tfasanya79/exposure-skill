import http.client
import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def _band(score, best):
    if best == 0:
        return "F"
    ratio = score / best
    if ratio >= 0.9:
        return "A"
    if ratio >= 0.75:
        return "B"
    if ratio >= 0.6:
        return "C"
    if ratio >= 0.4:
        return "D"
    return "F"


def _result(name, grade, findings, remediation):
    return {"check": name, "grade": grade, "findings": findings, "remediation": remediation}


def _key_info(host, port):
    # Python ssl does not expose the public key, so read the certificate text.
    # Returns (algorithm, bits, is_elliptic_curve).
    algorithm, bits, is_ec = "", 0, False
    try:
        pem = subprocess.run(
            ["openssl", "s_client", "-connect", "%s:%d" % (host, port), "-servername", host],
            input="", capture_output=True, text=True, timeout=20).stdout
        text = subprocess.run(["openssl", "x509", "-noout", "-text"], input=pem,
                              capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return algorithm, bits, is_ec
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Public Key Algorithm:"):
            algorithm = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Public-Key:"):
            match = re.search(r"(\d+) bit", stripped)
            if match:
                bits = int(match.group(1))
        elif "ASN1 OID" in stripped or "NIST CURVE" in stripped:
            is_ec = True
    return algorithm, bits, is_ec


def tls(host, port=443):
    findings, score, best = [], 0, 6
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=15) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                protocol = sock.version()
    except Exception as exc:
        return _result("tls", "F", [("fail", "Could not complete a TLS handshake: %s" % exc)],
                       "Confirm the host serves TLS on port %s." % port)

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days = (not_after - datetime.now(timezone.utc)).days
    if days >= 30:
        score += 2
        findings.append(("ok", "Certificate expires in %d days" % days))
    elif days >= 0:
        score += 1
        findings.append(("warn", "Certificate expires in %d days, renew soon" % days))
    else:
        findings.append(("fail", "Certificate expired %d days ago" % abs(days)))

    if protocol in ("TLSv1.2", "TLSv1.3"):
        score += 1
        findings.append(("ok", "Negotiated %s" % protocol))
    else:
        findings.append(("fail", "Negotiated %s, which is deprecated" % protocol))

    san = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    if host in san or ("*." + host.split(".", 1)[-1]) in san:
        score += 1
        findings.append(("ok", "Hostname is covered by the certificate"))
    else:
        findings.append(("fail", "Hostname is not in the certificate SAN list: %s" % ", ".join(san[:5])))

    algorithm, bits, is_ec = _key_info(host, port)
    if is_ec and bits >= 256:
        score += 1
        findings.append(("ok", "Elliptic curve key at %d bits (%s)" % (bits, algorithm or "EC")))
    elif (not is_ec) and bits >= 2048:
        score += 1
        findings.append(("ok", "RSA key at %d bits" % bits))
    elif bits == 0:
        findings.append(("warn", "Public key size could not be read on this host"))
    else:
        findings.append(("fail", "Public key is weak: %d bits (%s)" % (bits, algorithm or "unknown")))

    score += 1
    findings.append(("ok", "Chain of trust verified against the system store"))

    return _result("tls", _band(score, best), findings,
                   "Renew before expiry and keep TLS 1.2 as the floor.")


def _dig(name, rtype):
    try:
        out = subprocess.run(["dig", "+short", rtype, name], capture_output=True, text=True, timeout=15)
        return [line.strip().strip(chr(34)) for line in out.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def dns_auth(domain):
    findings = []

    spf = [record for record in _dig(domain, "TXT") if record.startswith("v=spf1")]
    dmarc = [record for record in _dig("_dmarc." + domain, "TXT") if record.startswith("v=DMARC1")]

    policy = "none"
    if dmarc:
        for part in dmarc[0].split(";"):
            if part.strip().startswith("p="):
                policy = part.strip()[2:]

    # A domain can deliberately send no mail. In that case v=spf1 -all plus a
    # DMARC reject policy is the correct, complete posture, and missing DKIM or
    # MX records are not findings. Detect that case before scoring.
    no_send = False
    if spf:
        tokens = spf[0].split()[1:]
        senders = [token for token in tokens if token not in ("-all", "~all", "all")]
        no_send = not senders and "-all" in tokens

    if no_send and policy in ("reject", "quarantine"):
        findings.append(("ok", "SPF is v=spf1 -all, so no host is authorised to send"))
        findings.append(("ok", "DMARC policy is %s" % policy))
        findings.append(("ok", "DKIM and MX are not applicable, this domain sends and receives no mail"))
        return _result("dns-auth", "A", findings,
                       "No action. Keep the records in place and re-check after any mail integration.")

    score, best = 0, 4

    if spf:
        score += 1
        findings.append(("ok", "SPF present: %s" % spf[0][:70]))
        if "-all" not in spf[0]:
            findings.append(("warn", "SPF does not end in -all, so it is permissive"))
    else:
        findings.append(("fail", "No SPF record, so anyone can send as this domain"))

    if dmarc:
        score += 1
        findings.append(("ok", "DMARC present with p=%s" % policy))
        if policy == "none":
            findings.append(("warn", "DMARC policy is none, so it only monitors"))
    else:
        findings.append(("fail", "No DMARC record"))

    dkim_found = False
    for selector in ("default", "google", "selector1", "selector2", "k1", "mail"):
        if _dig(selector + "._domainkey." + domain, "TXT"):
            score += 1
            dkim_found = True
            findings.append(("ok", "DKIM key found at selector %s" % selector))
            break
    if not dkim_found:
        findings.append(("warn", "No DKIM key at common selectors; selectors are not discoverable, so this is inconclusive"))

    if _dig(domain, "MX"):
        score += 1
        findings.append(("ok", "MX records present"))
    else:
        findings.append(("warn", "No MX records, this domain does not receive mail"))

    return _result("dns-auth", _band(score, best), findings,
                   "Publish SPF ending in -all, a DMARC policy of quarantine or reject, and rotate DKIM keys yearly.")


def headers(host):
    findings, score, best = [], 0, len(SECURITY_HEADERS)
    try:
        conn = http.client.HTTPSConnection(host, timeout=15)
        conn.request("GET", "/", headers={"User-Agent": "exposure-skill/0.1"})
        response = conn.getresponse()
        present = {key.lower() for key, _ in response.getheaders()}
        conn.close()
    except Exception as exc:
        return _result("headers", "F", [("fail", "Request failed: %s" % exc)],
                       "Confirm the site responds over HTTPS.")

    for header in SECURITY_HEADERS:
        if header in present:
            score += 1
            findings.append(("ok", header))
        else:
            findings.append(("warn", "%s missing" % header))

    return _result("headers", _band(score, best), findings,
                   "Add the missing headers at the edge, start with HSTS and CSP.")
