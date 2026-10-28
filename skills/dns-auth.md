# Skill: dns-auth

Use when the request is about email spoofing, SPF, DKIM, DMARC or deliverability.

Steps:

1. Confirm the scope. Stop if the domain is not listed.
2. Run the `dns-auth` check.
3. Explain that DKIM selectors are not discoverable, so a missing key at common selectors is inconclusive rather than a failure.
4. Recommend a DMARC policy of quarantine or reject once alignment is confirmed.
