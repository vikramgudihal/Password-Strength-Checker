"""Unit tests: scoring tiers, individual detectors, entropy maths, and privacy."""
import ast
import builtins
import math
import socket
import unittest
from pathlib import Path
from unittest import mock

from checker import analyze, entropy, patterns

ROOT = Path(__file__).resolve().parent.parent
SOURCES = [*ROOT.joinpath("checker").glob("*.py"), ROOT / "password_checker.py"]


class TestScoringTiers(unittest.TestCase):
    # ---- weak ----
    def test_weak_common_password(self):
        self.assertEqual(analyze("123456").rating, "Weak")

    def test_weak_leetspeak_substitution(self):
        a = analyze("p@ssw0rd")
        self.assertEqual(a.rating, "Weak")
        self.assertTrue(a.has("leetspeak") or a.has("dictionary"))

    def test_weak_keyboard_walk(self):
        a = analyze("qwerty123")
        self.assertEqual(a.rating, "Weak")
        self.assertTrue(a.has("sequence"))

    def test_weak_all_repeated(self):
        a = analyze("aaaaaaaaaaaa")
        self.assertEqual(a.rating, "Weak")
        self.assertTrue(a.has("repeat"))

    def test_weak_word_year(self):
        a = analyze("Summer2024!")
        self.assertEqual(a.rating, "Weak")
        self.assertTrue(a.has("year"))

    # ---- moderate ----
    def test_moderate(self):
        self.assertEqual(analyze("blue-Kettle-47").rating, "Moderate")

    # ---- strong ----
    def test_strong_random(self):
        self.assertIn(analyze("v8#Lq!zR2$mW9xTe").rating, ("Strong", "Very Strong"))

    def test_very_strong_long_random(self):
        self.assertEqual(analyze("Zk7!pQm2@Xw9#Lr4Bn6&Vd8^").rating, "Very Strong")

    def test_ordering_weak_lt_moderate_lt_strong(self):
        w = analyze("123456").score
        m = analyze("blue-Kettle-47").score
        s = analyze("v8#Lq!zR2$mW9xTe").score
        self.assertLess(w, m)
        self.assertLess(m, s)

    def test_empty_password(self):
        a = analyze("")
        self.assertEqual(a.rating, "Weak")
        self.assertEqual(a.score, 0)

    def test_non_string_rejected_without_echoing_value(self):
        with self.assertRaises(TypeError) as ctx:
            analyze(12345)
        self.assertNotIn("12345", str(ctx.exception))


class TestFeedback(unittest.TestCase):
    def test_suggests_missing_classes(self):
        s = " ".join(analyze("abcdefgh").suggestions)
        self.assertIn("uppercase", s)
        self.assertIn("numbers", s)
        self.assertIn("special", s)

    def test_suggests_length(self):
        self.assertTrue(any("length" in s for s in analyze("Ab1!").suggestions))

    def test_leet_feedback_mentions_substitution(self):
        a = analyze("P@ssw0rd")
        text = " ".join(f.detail for f in a.findings).lower()
        self.assertIn("substitution", text)


class TestDetectors(unittest.TestCase):
    def test_normalize_leet(self):
        self.assertIn("password", patterns.normalize_leet("P@$$w0rd"))

    def test_normalize_leet_ambiguous_one(self):
        variants = patterns.normalize_leet("1ove")
        self.assertIn("iove", variants)
        self.assertIn("love", variants)

    def test_repeats(self):
        self.assertEqual(patterns.find_repeats("xaaay111z"), ["aaa", "111"])
        self.assertEqual(patterns.find_repeats("aabbcc"), [])

    def test_sequences(self):
        self.assertEqual(patterns.find_sequences("x1234y"), ["1234"])
        self.assertEqual(patterns.find_sequences("abcdef"), ["abcdef"])
        self.assertEqual(patterns.find_sequences("9876"), ["9876"])
        self.assertEqual(patterns.find_sequences("QWERTY"), ["qwerty"])
        self.assertEqual(patterns.find_sequences("asdf"), ["asdf"])
        self.assertEqual(patterns.find_sequences("a1c3e5"), [])

    def test_years(self):
        self.assertEqual(patterns.find_years("pw1998x2024"), ["1998", "2024"])
        self.assertEqual(patterns.find_years("pw3098"), [])

    def test_dictionary_exact(self):
        m = patterns.find_dictionary_matches("password")
        self.assertTrue(any(x["word"] == "password" and x["exact"] for x in m))

    def test_dictionary_disguised(self):
        m = patterns.find_dictionary_matches("P@55w0rD")
        self.assertTrue(any(x["word"] == "password" and x["disguised"] for x in m))

    def test_dictionary_embedded(self):
        m = patterns.find_dictionary_matches("xx-dragon-qZ9")
        self.assertTrue(any(x["word"] == "dragon" for x in m))

    def test_random_string_has_no_dictionary_match(self):
        self.assertEqual(patterns.find_dictionary_matches("v8#Lq!zR2$mW9xTe"), [])


class TestEntropy(unittest.TestCase):
    def test_pool_sizes(self):
        self.assertEqual(entropy.pool_size("abc"), 26)
        self.assertEqual(entropy.pool_size("aB"), 52)
        self.assertEqual(entropy.pool_size("aB1"), 62)
        self.assertEqual(entropy.pool_size("aB1!"), 62 + 33)

    def test_pool_entropy_formula(self):
        self.assertAlmostEqual(entropy.pool_entropy("abcdefgh"), 8 * math.log2(26))
        self.assertEqual(entropy.pool_entropy(""), 0.0)

    def test_shannon_zero_for_repeated_char(self):
        self.assertEqual(entropy.shannon_per_char("aaaaaaaa"), 0.0)

    def test_shannon_known_values(self):
        self.assertAlmostEqual(entropy.shannon_per_char("abcd"), 2.0)
        self.assertAlmostEqual(entropy.shannon_per_char("aabb"), 1.0)
        self.assertAlmostEqual(entropy.shannon_total("abcdefgh"), 24.0)

    def test_effective_entropy_is_minimum(self):
        pw = "aaaaaaaaaaaaaaaa"
        self.assertEqual(entropy.effective_entropy(pw), 0.0)
        self.assertLess(entropy.effective_entropy(pw), entropy.pool_entropy(pw))


class TestPrivacy(unittest.TestCase):
    FORBIDDEN_IMPORTS = {"socket", "requests", "urllib", "urllib3", "http", "httpx",
                         "ftplib", "smtplib", "telnetlib", "logging", "pickle",
                         "shelve", "sqlite3", "subprocess", "tempfile", "webbrowser"}

    def _trees(self):
        for path in SOURCES:
            yield path, ast.parse(path.read_text(encoding="utf-8"))

    def test_no_network_logging_or_storage_imports(self):
        for path, tree in self._trees():
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module.split(".")[0]]
                bad = set(names) & self.FORBIDDEN_IMPORTS
                self.assertFalse(bad, f"{path.name} imports forbidden module(s): {bad}")

    def test_no_file_writes(self):
        for path, tree in self._trees():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "open":
                    mode = "r"
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                        mode = node.args[1].value
                    for kw in node.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                            mode = kw.value.value
                    self.assertFalse(set(mode) & set("wax+"),
                                     f"{path.name} opens a file for writing")
                if isinstance(node, ast.Attribute) and node.attr in (
                        "write_text", "write_bytes"):
                    self.fail(f"{path.name} uses {node.attr}")

    def test_no_print_in_library_code(self):
        for path in (ROOT / "checker").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "print":
                    self.fail(f"{path.name} calls print()")

    def test_runtime_no_network_and_no_writes(self):
        real_open = builtins.open

        def guarded_open(file, mode="r", *a, **k):
            self.assertFalse(set(mode) & set("wax+"), "write attempted")
            return real_open(file, mode, *a, **k)

        patterns.common_passwords.cache_clear()
        patterns._long_words.cache_clear()
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network!")), \
             mock.patch.object(socket, "create_connection", side_effect=AssertionError("network!")), \
             mock.patch("builtins.open", guarded_open):
            for pw in ("123456", "p@ssw0rd", "v8#Lq!zR2$mW9xTe"):
                analyze(pw)

    def test_result_does_not_contain_password(self):
        secret = "Zq8#unique-Secret-Marker!"
        a = analyze(secret)
        blob = repr(a) + str(a)
        self.assertNotIn(secret, blob)
        for value in vars(a).values():
            self.assertNotEqual(value, secret)

    def test_no_logging_emitted(self):
        with self.assertNoLogs(level="DEBUG"):
            analyze("p@ssw0rd")


if __name__ == "__main__":
    unittest.main()
