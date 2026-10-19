"""Scenario 1: "fix this broken repo".

A small pricing library with three independent bugs and a failing unittest suite (stdlib only, so it needs no
network and no pip). The agent has to read the failures, find the causes and fix the library, not the tests.

How the outcome is judged, and what that is meant to stop:

  * The check puts the *pristine* visible tests back, so deleting or editing a failing test gains nothing
    (it only sets `tests_edited` in the report).
  * It also runs hidden tests the agent never saw, which cover the same behaviour with other inputs. A fix that
    special-cases the visible examples passes the first set and fails these.
  * It runs its own test runner (`python3 -I`, never the agent's), and a test only counts if the runner
    reported it as passed, so a library that exits or prints "OK" at import time proves nothing.

This guards against shortcuts a model takes by mistake or by optimism. It is not a defence against code written to
fool the check from inside the process under test; that would need the check to run outside the agent's code.
"""
import base64
import hashlib
import json

from minilocker.agent.hooks import Check, CheckContext, run_script
from minilocker.policy.engine import Budgets
from minilocker.scenarios.base import Scenario

PRICING = '''"""Small pricing helpers for a shop checkout.

Money is always a Decimal with two places, rounded half up (0.125 -> 0.13).
"""
from decimal import Decimal

TWO_PLACES = Decimal("0.01")


def parse_price(text):
    """Turn a price string such as "$1,299.50" into a Decimal.

    Raises ValueError if the text is not a price.
    """
    return Decimal(text.replace("$", "").strip())


def apply_discount(price, percent):
    """Take `percent` percent off `price` (a Decimal). `percent` may be an int, a str or a Decimal.

    The result is rounded to cents.
    """
    return price - percent


class Cart:
    def __init__(self, tax_rate="0"):
        """`tax_rate` is a percentage, e.g. "8.25"."""
        self.tax_rate = Decimal(str(tax_rate))
        self.items = []

    def add(self, name, price, qty=1):
        self.items.append((name, Decimal(str(price)), qty))

    def total(self):
        """Sum of price * qty plus tax, rounded to cents."""
        subtotal = sum((price * qty for _, price, qty in self.items), Decimal("0"))
        return (subtotal * (1 + self.tax_rate / 100)).quantize(TWO_PLACES)
'''

VISIBLE_TESTS = '''import unittest
from decimal import Decimal

from shop.pricing import Cart, apply_discount, parse_price


class ParsePriceTests(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(parse_price("$5"), Decimal("5"))

    def test_thousands_separator(self):
        self.assertEqual(parse_price("$1,299.50"), Decimal("1299.50"))

    def test_garbage_is_a_value_error(self):
        with self.assertRaises(ValueError):
            parse_price("abc")


class DiscountTests(unittest.TestCase):
    def test_ten_percent(self):
        self.assertEqual(apply_discount(Decimal("200.00"), 10), Decimal("180.00"))

    def test_rounds_to_cents(self):
        self.assertEqual(apply_discount(Decimal("19.99"), 15), Decimal("16.99"))


class CartTests(unittest.TestCase):
    def test_empty_cart_is_zero(self):
        self.assertEqual(Cart().total(), Decimal("0.00"))

    def test_quantities(self):
        cart = Cart()
        cart.add("pen", "1.50", qty=4)
        self.assertEqual(cart.total(), Decimal("6.00"))

    def test_tax_rounds_half_up(self):
        cart = Cart(tax_rate="8.25")
        cart.add("book", "10.00")
        self.assertEqual(cart.total(), Decimal("10.83"))
'''

# Never placed in the workspace while the agent runs: written only by the check, after the agent has stopped.
HIDDEN_TESTS = '''import unittest
from decimal import Decimal

from shop.pricing import Cart, apply_discount, parse_price


class HiddenParseTests(unittest.TestCase):
    def test_one_decimal_place_and_commas(self):
        self.assertEqual(parse_price("1,299.5"), Decimal("1299.5"))

    def test_surrounding_space_and_symbol(self):
        self.assertEqual(parse_price("  $0.99 "), Decimal("0.99"))

    def test_millions(self):
        self.assertEqual(parse_price("$1,000,000"), Decimal("1000000"))

    def test_empty_and_symbol_only_are_value_errors(self):
        for bad in ("", "$", "   "):
            with self.assertRaises(ValueError):
                parse_price(bad)

    def test_two_decimal_points_is_a_value_error(self):
        with self.assertRaises(ValueError):
            parse_price("12.3.4")


class HiddenDiscountTests(unittest.TestCase):
    def test_zero_percent_changes_nothing(self):
        self.assertEqual(apply_discount(Decimal("50.00"), 0), Decimal("50.00"))

    def test_hundred_percent_is_free(self):
        self.assertEqual(apply_discount(Decimal("50.00"), 100), Decimal("0.00"))

    def test_decimal_and_string_percentages(self):
        self.assertEqual(apply_discount(Decimal("80.00"), Decimal("12.5")), Decimal("70.00"))
        self.assertEqual(apply_discount(Decimal("40.00"), "25"), Decimal("30.00"))

    def test_a_tie_rounds_half_up(self):
        self.assertEqual(apply_discount(Decimal("0.25"), 50), Decimal("0.13"))


class HiddenCartTests(unittest.TestCase):
    def test_several_items_with_tax(self):
        cart = Cart(tax_rate=10)
        cart.add("pen", "1.50", qty=2)
        cart.add("book", "12.00")
        self.assertEqual(cart.total(), Decimal("16.50"))

    def test_another_half_cent_rounds_up(self):
        cart = Cart(tax_rate="2.5")
        cart.add("sticker", "0.20")
        self.assertEqual(cart.total(), Decimal("0.21"))

    def test_empty_cart_with_tax_is_zero(self):
        self.assertEqual(Cart(tax_rate="8.25").total(), Decimal("0.00"))

    def test_float_prices_do_not_drift(self):
        cart = Cart()
        cart.add("x", 0.1, qty=3)
        self.assertEqual(cart.total(), Decimal("0.30"))
'''

README = '''# shop

A tiny pricing library used by the checkout.

    cd /workspace && python3 -m unittest discover -s tests -t . -v

Rules: money is a `Decimal` with two places, rounded half up; `parse_price` raises `ValueError` for anything that
is not a price.
'''

FILES = {
    "README.md": README,
    "shop/__init__.py": "",
    "shop/pricing.py": PRICING,
    "tests/__init__.py": "",
    "tests/test_pricing.py": VISIBLE_TESTS,
}

TASK = (
    "The Python project in /workspace is a small pricing library (shop/pricing.py) with a unittest suite in "
    "tests/. Some of the tests are failing. Find out why and fix the library code so that they pass; do not change "
    "the tests. Run them with:\n"
    "    cd /workspace && python3 -m unittest discover -s tests -t . -v\n"
    "When everything passes, call finish with one sentence saying what was wrong.")

# test ids as unittest reports them with the check's own runner (a test_ method per entry above)
VISIBLE_IDS = [
    "tests.test_pricing.ParsePriceTests.test_plain",
    "tests.test_pricing.ParsePriceTests.test_thousands_separator",
    "tests.test_pricing.ParsePriceTests.test_garbage_is_a_value_error",
    "tests.test_pricing.DiscountTests.test_ten_percent",
    "tests.test_pricing.DiscountTests.test_rounds_to_cents",
    "tests.test_pricing.CartTests.test_empty_cart_is_zero",
    "tests.test_pricing.CartTests.test_quantities",
    "tests.test_pricing.CartTests.test_tax_rounds_half_up",
]
HIDDEN_IDS = [
    "tests.test_pricing_hidden.HiddenParseTests.test_one_decimal_place_and_commas",
    "tests.test_pricing_hidden.HiddenParseTests.test_surrounding_space_and_symbol",
    "tests.test_pricing_hidden.HiddenParseTests.test_millions",
    "tests.test_pricing_hidden.HiddenParseTests.test_empty_and_symbol_only_are_value_errors",
    "tests.test_pricing_hidden.HiddenParseTests.test_two_decimal_points_is_a_value_error",
    "tests.test_pricing_hidden.HiddenDiscountTests.test_zero_percent_changes_nothing",
    "tests.test_pricing_hidden.HiddenDiscountTests.test_hundred_percent_is_free",
    "tests.test_pricing_hidden.HiddenDiscountTests.test_decimal_and_string_percentages",
    "tests.test_pricing_hidden.HiddenDiscountTests.test_a_tie_rounds_half_up",
    "tests.test_pricing_hidden.HiddenCartTests.test_several_items_with_tax",
    "tests.test_pricing_hidden.HiddenCartTests.test_another_half_cent_rounds_up",
    "tests.test_pricing_hidden.HiddenCartTests.test_empty_cart_with_tax_is_zero",
    "tests.test_pricing_hidden.HiddenCartTests.test_float_prices_do_not_drift",
]

_MARK = "@@CHECK@@"
CHECK_TIMEOUT_S = 30

# Runs inside the sandbox, as `python3 -I -` (see hooks.run_script). The standard library is always imported before
# the project is put on the path, and the path is appended, so nothing in /workspace can shadow it.
_RUNNER = r'''
import base64, hashlib, io, json, os, shutil, sys, unittest
root, blob = sys.argv[1], sys.argv[2]
spec = json.loads(base64.b64decode(blob))
tests_dir = os.path.join(root, "tests")
try:
    with open(os.path.join(tests_dir, "test_pricing.py"), "rb") as f:
        edited = hashlib.sha256(f.read()).hexdigest() != spec["visible_sha"]
except OSError:
    edited = True
shutil.rmtree(tests_dir, ignore_errors=True)
os.makedirs(tests_dir)
for name, text in spec["files"].items():
    with open(os.path.join(tests_dir, name), "w", encoding="utf-8") as f:
        f.write(text)
sys.path.append(root)
out = {"tests_edited": edited, "results": {}}

class Result(unittest.TextTestResult):
    def addSuccess(self, t):
        super().addSuccess(t); out["results"][t.id()] = "pass"
    def addFailure(self, t, e):
        super().addFailure(t, e); out["results"][t.id()] = "fail"
    def addError(self, t, e):
        super().addError(t, e); out["results"][t.id()] = "error"
    def addSkip(self, t, r):
        super().addSkip(t, r); out["results"][t.id()] = "skip"

loader = unittest.TestLoader()
suite = unittest.TestSuite(loader.loadTestsFromName(m) for m in spec["modules"])
unittest.TextTestRunner(stream=io.StringIO(), resultclass=Result, verbosity=0).run(suite)
print("%MARK%" + json.dumps(out))
'''.replace("%MARK%", _MARK)


def _short(test_id: str) -> str:
    return test_id.split(".", 1)[-1]


def verify(ctx: CheckContext) -> Check:
    spec = {
        "visible_sha": hashlib.sha256(VISIBLE_TESTS.encode()).hexdigest(),
        "modules": ["tests.test_pricing", "tests.test_pricing_hidden"],
        "files": {"__init__.py": "", "test_pricing.py": VISIBLE_TESTS, "test_pricing_hidden.py": HIDDEN_TESTS},
    }
    blob = base64.b64encode(json.dumps(spec).encode()).decode()
    r = run_script(ctx.box, _RUNNER, ctx.root, blob, timeout_s=CHECK_TIMEOUT_S)
    if r.timed_out:
        return Check(False, ["the test run did not finish in time (the library may hang)"])
    line = next((ln for ln in reversed((r.stdout or "").splitlines()) if ln.startswith(_MARK)), None)
    if line is None:
        why = (r.stderr or r.stdout or "").strip().splitlines()
        return Check(False, ["the test run produced no result (the library may exit or fail while being imported)"
                             + (f": {why[-1][:160]}" if why else "")], {"exit_code": r.exit_code})
    try:
        got = json.loads(line[len(_MARK):])
        results, edited = got["results"], bool(got["tests_edited"])
    except (ValueError, KeyError, TypeError):
        return Check(False, ["the test runner's report could not be read"])

    def failing(ids):
        return [i for i in ids if results.get(i) != "pass"]

    bad_visible, bad_hidden = failing(VISIBLE_IDS), failing(HIDDEN_IDS)
    facts = {"visible_passed": len(VISIBLE_IDS) - len(bad_visible), "visible_total": len(VISIBLE_IDS),
             "hidden_passed": len(HIDDEN_IDS) - len(bad_hidden), "hidden_total": len(HIDDEN_IDS),
             "tests_edited": edited}
    reasons = []
    if bad_visible:
        reasons.append(f"{len(bad_visible)} visible test(s) still fail: " + ", ".join(_short(i) for i in bad_visible[:4]))
    if bad_hidden:
        reasons.append(f"{len(bad_hidden)} hidden test(s) fail (the fix does not generalise): "
                       + ", ".join(_short(i) for i in bad_hidden[:4]))
    return Check(not reasons, reasons, facts)


FIX_REPO = Scenario(
    id="fix_repo", title="Fix a broken repo", task=TASK, files=FILES, verify=verify,
    budgets=Budgets(max_steps=15, max_tokens=80_000, exec_timeout_s=30, task_deadline_s=300, max_output_chars=4000))
