Password Strength Analyzer

A command-line tool, written in Python, that scores a password out of 100 by checking for the patterns attackers actually exploit, not just length and character types.

## What it checks

- Length (minimum 12 characters)
- Character types (lowercase, uppercase, digits, symbols)
- Common passwords (SecLists top 1000, case-insensitive)
- Repeated characters (`aaa`), sequences (`123`, `abc`), keyboard walks (`qwer`)
- Years (`1987`, `2024`) and common words hidden inside the password
- Repeated chunks (`abcabc`) and repeated words in passphrases
- Predictable shape: word, then digits, then symbols (`Summer2024!`)
- Optional personal info: names, reversed, leetspeak, and hex/binary/ASCII digit forms
- Entropy: `length x log2(charset size)`, or `words x 12.9` for passphrases

Each failed check subtracts penalty points from the entropy-based score.

## Setup

python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

No external packages are needed. Download `10-million-password-list-top-1000.txt` from [SecLists](https://github.com/danielmiessler/SecLists) (Passwords > Common-Credentials) and save it in this folder as `common_passwords.txt`.

## Usage

python analyzer.py
Enter optional names when asked (or press Enter to skip), then type the password. Input is hidden.

Example verdicts:

| Password | Result |
|---|---|
| `password` | Weak (0) |
| `Summer2024!` | Weak |
| `kT9#mPz2vL!q` | Strong |

## Tests


python -m unittest -v

The `TestRealWorldRegressions` tests record passwords that fooled earlier versions, so those bugs can't return.

## Known limitations

- Entropy assumes characters are random. The analyzer sees only the finished string, so it can't tell a randomly generated password from one a person invented.
- Passphrase scores assume the words were chosen randomly (e.g. by dice or a generator).
- It cannot detect a derivation it doesn't know about, such as digits built from a name using a custom scheme.
- A score is an estimate, not a guarantee. For real accounts, use a password manager and two-factor authentication.

## Safety

Test with made-up passwords only. Never enter a real password you use anywhere.

## Comparison with zxcvbn

I ran eight test passwords through this analyzer and Dropbox's `zxcvbn`.

- **Agreement:** both rate `password`, `hello123` and `Summer2024!` as weak.
- **zxcvbn is better** at `- **zxcvbn exposed a bug** in `helloworldhelloworld`: repeated parts inflated my entropy. Fixed by collapsing repeats before measuring entropy, with regression tests.
- **This analyzer is better** at predictable structure: `nforblaise58092@` gets 4/4 from zxcvbn unless it is given the name via `user_inputs`, while my structure and personal-info checks flag it.
- **zxcvbn is more generous with passphrases** and appears to penalize non-adjacent repeated words less (`plug-treats-plug-us-plug`).
- zxcvbn estimates unrecognised characters at a flat 10 guesses each, so its guess count for truly random strings is far lower than the real figure.

Takeaway: no single scoring method is reliable alone. Combining entropy, pattern checks and personal context works best, and the real defense is a randomly generated password from a password manager.
Possible next steps
