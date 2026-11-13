from zxcvbn import zxcvbn

import analyzer

# Made-up test passwords only. Never put real passwords here.
TEST_PASSWORDS = [
    "password",
    "hello123",
    "Summer2024!",
    "helloworldhelloworld",
    "nforblaise58092@",
    "plug-treats-plug-us-plug",
    "plum-staple-orbit-violin",
    "kT9#mPz2vL!q",
]


def main():
    common = analyzer.load_common_passwords()

    print(f"{'Password':<28}{'Mine':>6}  {'zxcvbn (0-4)':>12}  {'zxcvbn guesses (log10)':>22}")
    print("-" * 72)

    for pw in TEST_PASSWORDS:
        mine = analyzer.analyze(pw, common)["score"]
        z = zxcvbn(pw)
        print(f"{pw:<28}{mine:>6}  {z['score']:>12}  {z['guesses_log10']:>22.1f}")


if __name__ == "__main__":
    main()