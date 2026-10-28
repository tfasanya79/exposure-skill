
import json
from datetime import date

REQUIRED = ("authorised", "authorisation_reference", "expires", "targets")


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def validate(scope, target):
    # Returns a list of problems. An empty list means the run is authorised.
    problems = []
    for key in REQUIRED:
        if key not in scope:
            problems.append("missing field: %s" % key)
    if problems:
        return problems

    if scope.get("authorised") is not True:
        problems.append("authorised must be literally true")
    if not str(scope.get("authorisation_reference", "")).strip():
        problems.append("authorisation_reference is empty; record the ticket, contract or written approval")

    try:
        expiry = date.fromisoformat(str(scope.get("expires")))
        if expiry < date.today():
            problems.append("scope expired on %s" % expiry)
    except ValueError:
        problems.append("expires must be an ISO date, YYYY-MM-DD")

    targets = [str(t).strip().lower() for t in scope.get("targets", [])]
    if target.strip().lower() not in targets:
        problems.append("target %s is not in the authorised target list" % target)

    return problems
