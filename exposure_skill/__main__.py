
import argparse
import sys

from . import checks, report, scope as scope_mod

CHECK_MAP = {"tls": checks.tls, "dns-auth": checks.dns_auth, "headers": checks.headers}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="exposure-skill",
                                     description="Authorised exposure assessment. Refuses to run without a scope file.")
    parser.add_argument("--scope", required=True, help="path to the scope JSON file")
    parser.add_argument("--target", required=True, help="domain you are authorised to assess")
    parser.add_argument("--checks", default="tls,dns-auth,headers", help="comma separated checks")
    parser.add_argument("--out", help="write the markdown report here")
    args = parser.parse_args(argv)

    loaded = scope_mod.load(args.scope)
    problems = scope_mod.validate(loaded, args.target)
    if problems:
        print("Refusing to run. The scope gate failed:", file=sys.stderr)
        for problem in problems:
            print("  - %s" % problem, file=sys.stderr)
        return 2

    results = []
    for name in [c.strip() for c in args.checks.split(",") if c.strip()]:
        if name not in CHECK_MAP:
            print("Unknown check: %s" % name, file=sys.stderr)
            return 2
        results.append(CHECK_MAP[name](args.target))

    text = report.render(args.target, loaded, results)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print("wrote %s" % args.out)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
