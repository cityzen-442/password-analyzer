import unittest

import analyzer

# A tiny blocklist so tests don't depend on the big SecLists file
COMMON = {"password", "qwerty", "hello", "summer", "123456", "letmein"}


class TestBasicChecks(unittest.TestCase):
    def test_length(self):
        self.assertFalse(analyzer.check_length("hello")[0])
        self.assertFalse(analyzer.check_length("Summer2024!")[0])  # 11 chars
        self.assertTrue(analyzer.check_length("kT9#mPz2vL!q")[0])  # 12 chars

    def test_character_types(self):
        types = analyzer.check_character_types("Hello1!")
        self.assertTrue(all(types.values()))
        types = analyzer.check_character_types("hello")
        self.assertTrue(types["lowercase"])
        self.assertFalse(types["uppercase"])
        self.assertFalse(types["digit"])
        self.assertFalse(types["symbol"])

    def test_common_password_is_case_insensitive(self):
        self.assertFalse(analyzer.check_common_password("password", COMMON)[0])
        self.assertFalse(analyzer.check_common_password("PASSWORD", COMMON)[0])
        self.assertTrue(analyzer.check_common_password("kT9#mPz2vL!q", COMMON)[0])


class TestPatternChecks(unittest.TestCase):
    def test_repeats(self):
        self.assertFalse(analyzer.check_repeats("aaaBBB")[0])
        self.assertTrue(analyzer.check_repeats("kT9#mPz2vL!q")[0])

    def test_sequences(self):
        self.assertFalse(analyzer.check_sequences("hello123")[0])
        self.assertFalse(analyzer.check_sequences("xxcbaxx")[0])  # backwards
        self.assertTrue(analyzer.check_sequences("kT9#mPz2vL!q")[0])

    def test_keyboard_walks(self):
        self.assertFalse(analyzer.check_keyboard_walks("qwerty99")[0])
        self.assertTrue(analyzer.check_keyboard_walks("kT9#mPz2vL!q")[0])

    def test_years(self):
        self.assertFalse(analyzer.check_years("Summer2024!")[0])
        self.assertTrue(analyzer.check_years("kT9#mPz2vL!q")[0])

    def test_common_words_hidden_inside(self):
        self.assertFalse(analyzer.check_common_words("Summer2024!", COMMON)[0])
        self.assertTrue(analyzer.check_common_words("kT9#mPz2vL!q", COMMON)[0])

    def test_repeated_chunks(self):
        self.assertFalse(analyzer.check_repeated_chunks("helloworldhelloworld")[0])
        self.assertTrue(analyzer.check_repeated_chunks("kT9#mPz2vL!q")[0])

    def test_structure(self):
        self.assertFalse(analyzer.check_structure("nforblaise58092@")[0])
        self.assertFalse(analyzer.check_structure("Summer2024!")[0])
        self.assertTrue(analyzer.check_structure("kT9#mPz2vL!q")[0])


class TestPassphrases(unittest.TestCase):
    def test_detects_passphrase(self):
        words = analyzer.detect_passphrase("plum-staple-orbit-violin")
        self.assertEqual(len(words), 4)
        self.assertIsNone(analyzer.detect_passphrase("Summer2024!"))

    def test_two_letter_words_still_count(self):
        # Bug we found: 'us' used to stop this being seen as a passphrase
        self.assertIsNotNone(analyzer.detect_passphrase("plug-treats-plug-us-plug"))

    def test_duplicate_words(self):
        self.assertFalse(analyzer.check_duplicate_words(["plug", "a", "plug"])[0])
        self.assertTrue(analyzer.check_duplicate_words(["plum", "staple"])[0])

    def test_passphrase_entropy(self):
        bits = analyzer.calculate_passphrase_entropy(["plum", "staple", "orbit", "violin"])
        self.assertAlmostEqual(bits, 51.6, places=1)


class TestPersonalInfo(unittest.TestCase):
    def test_skipped_when_empty(self):
        self.assertTrue(analyzer.check_personal_info("anything", [])[0])

    def test_direct_name(self):
        self.assertFalse(analyzer.check_personal_info("nforblaise58092@", ["blaise"])[0])

    def test_reversed_name(self):
        self.assertFalse(analyzer.check_personal_info("esialb99", ["blaise"])[0])

    def test_leetspeak(self):
        self.assertFalse(analyzer.check_personal_info("Bl4ise!xyz", ["blaise"])[0])

    def test_hex_value_of_name(self):
        # 'dead' read as hex is 57005
        self.assertFalse(analyzer.check_personal_info("Zara57005#", ["dead"])[0])

    def test_unrelated_password_passes(self):
        self.assertTrue(analyzer.check_personal_info("kT9#mPz2vL!q", ["blaise"])[0])


class TestEntropyAndScore(unittest.TestCase):
    def test_entropy_values(self):
        self.assertAlmostEqual(analyzer.calculate_entropy("hello"), 23.5, places=1)
        self.assertEqual(analyzer.calculate_entropy(""), 0.0)

    def test_score_subtracts_penalties(self):
        results = [("length", False, "too short")]
        self.assertEqual(analyzer.calculate_score(50, results), 40)

    def test_score_never_below_zero(self):
        results = [("common", False, "common")]
        self.assertEqual(analyzer.calculate_score(30, results), 0)

    def test_verdict_boundaries(self):
        self.assertEqual(analyzer.verdict(39), "Weak")
        self.assertEqual(analyzer.verdict(40), "Fair")
        self.assertEqual(analyzer.verdict(60), "Strong")
        self.assertEqual(analyzer.verdict(80), "Very strong")


class TestRealWorldRegressions(unittest.TestCase):
    """Passwords that fooled the analyzer earlier. They must stay caught."""

    def score(self, password, items=None):
        return analyzer.analyze(password, COMMON, items)["score"]

    def test_common_password_scores_zero(self):
        self.assertEqual(self.score("password"), 0)

    def test_summer2024_is_weak(self):
        self.assertLess(self.score("Summer2024!"), 40)

    def test_plug_treats_plug_is_weak(self):
        self.assertLess(self.score("plug-treats-plug-us-plug"), 40)

    def test_name_digits_symbol_is_not_very_strong(self):
        self.assertLess(self.score("nforblaise58092@"), 80)

    def test_name_digits_symbol_with_personal_info_is_weak(self):
        self.assertLess(self.score("nforblaise58092@", ["blaise"]), 40)

    def test_random_password_is_strong(self):
        self.assertGreaterEqual(self.score("kT9#mPz2vL!q"), 60)

    def test_random_passphrase_is_fair(self):
        self.assertEqual(self.score("plum-staple-orbit-violin"), 52)
class TestRepeatCollapsing(unittest.TestCase):
    """Bug found by comparing with zxcvbn: repeats inflated entropy."""

    def test_collapse_repeated_chunk(self):
        self.assertEqual(analyzer.collapse_repeats("helloworldhelloworld"), "helloworld")

    def test_collapse_run_of_characters(self):
        self.assertEqual(analyzer.collapse_repeats("xaaaay"), "xay")

    def test_random_password_unchanged(self):
        self.assertEqual(analyzer.collapse_repeats("kT9#mPz2vL!q"), "kT9#mPz2vL!q")

    def test_repeat_adds_no_entropy(self):
        doubled = analyzer.calculate_entropy("helloworldhelloworld")
        single = analyzer.calculate_entropy("helloworld")
        self.assertAlmostEqual(doubled, single, places=1)

    def test_helloworldhelloworld_is_weak(self):
        score = analyzer.analyze("helloworldhelloworld", COMMON)["score"]
        self.assertLess(score, 40)

if __name__ == "__main__":
    unittest.main()