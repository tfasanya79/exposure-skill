# exposure-skill

An authorised exposure assessment skill pack. A scope gate, a router, and a report that a manager can read.

Most security tooling assumes you already have permission. This one makes permission a precondition: it refuses to run unless a scope file names the target, states who authorised the work, and has not expired.

## Why

Pointing a scanner at a domain you do not own is not a clever trick, it is a disciplinary matter. The gate is the feature.

## What it checks

| Skill | What it does |
|-------|--------------|
| `tls` | Certificate expiry, chain of trust, negotiated protocol version, hostname coverage, key strength |
| `dns-auth` | SPF, DMARC policy and DKIM presence, plus MX |
| `headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |

Each check returns a grade from A to F and a remediation line, and the report is plain markdown so it drops into a ticket.

## Usage

```bash
cp scope.example.json scope.json
# edit scope.json: authorisation reference, expiry, and the targets you may assess

python3 -m exposure_skill --scope scope.json --target example.com --out report.md
```

The gate rejects the run with a non zero exit code if any of these are true:

- `authorised` is not literally `true`
- `authorisation_reference` is empty
- `expires` is in the past
- the target is not listed in `targets`

## Design notes

- Standard library only, so it runs anywhere Python 3.9 or later exists
- Read only: no writes to the target, no exploitation, no brute force
- Every finding carries a plain English explanation and a remediation step

## Agent skills

The `skills/` directory holds short SKILL.md definitions so an AI coding agent can route a request to the right check and remember the authorisation gate. Written for Claude Code, Cursor and Cline style clients.

## Licence

MIT. See LICENSE.
