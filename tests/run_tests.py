import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import tests.test_scope as suite  # noqa: E402

failures = 0
for name in sorted(dir(suite)):
    if not name.startswith("test_"):
        continue
    try:
        getattr(suite, name)()
        print("pass  %s" % name)
    except AssertionError:
        failures += 1
        print("FAIL  %s" % name)
print()
print("failures: %d" % failures)
sys.exit(1 if failures else 0)
