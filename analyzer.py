import re
from getpass import getpass


def check_character_types(password):
    """Return which character categories the password contains."""
    return {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }


def main():
    password = getpass("Enter a password to analyze: ")
    print(f"Length: {len(password)}")
    for category, present in check_character_types(password).items():
        print(f"{category}: {'yes' if present else 'no'}")


if __name__ == "__main__":
    main()