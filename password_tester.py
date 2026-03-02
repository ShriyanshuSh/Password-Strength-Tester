import requests
import hashlib
import getpass
from zxcvbn import zxcvbn


class PasswordStrengthTester:
    def __init__(self, check_pwned=False):
        self.check_pwned = check_pwned

    def evaluate_password(self, password: str) -> dict:
        """
        Evaluate password strength using zxcvbn.
        """
        result = zxcvbn(password)

        strength_levels = [
            "Very Weak",
            "Weak",
            "Fair",
            "Strong",
            "Very Strong"
        ]

        score = result["score"]
        feedback = result["feedback"]

        return {
            "score": score,
            "strength": strength_levels[score],
            "crack_time": result["crack_times_display"]["offline_fast_hashing_1e10_per_second"],
            "feedback": feedback
        }

    def check_haveibeenpwned(self, password: str) -> int:
        """
        Check password against Have I Been Pwned database using k-anonymity.
        Returns number of times the password was found in breaches.
        """
        sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)

        if response.status_code != 200:
            print("⚠ Error checking breach database.")
            return -1

        hashes = response.text.splitlines()

        for line in hashes:
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)

        return 0

    def display_results(self, analysis: dict, pwned_count: int = None):
        print("\n===== Password Strength Report =====")
        print(f"Strength: {analysis['strength']} (Score: {analysis['score']}/4)")
        print(f"Estimated Crack Time: {analysis['crack_time']}")

        if analysis["feedback"]["warning"]:
            print(f"\n⚠ Warning: {analysis['feedback']['warning']}")

        if analysis["feedback"]["suggestions"]:
            print("\nSuggestions:")
            for suggestion in analysis["feedback"]["suggestions"]:
                print(f" - {suggestion}")

        if pwned_count is not None:
            print("\n===== Breach Check =====")
            if pwned_count > 0:
                print(f"❌ This password has appeared in data breaches {pwned_count} times!")
                print("Recommendation: Do NOT use this password.")
            elif pwned_count == 0:
                print("✅ This password was NOT found in known breaches.")
            else:
                print("⚠ Could not verify breach status.")

        print("====================================\n")


def main():
    print("🔐 Password Strength Tester")
    print("---------------------------")

    password = getpass.getpass("Enter password to evaluate: ")

    choice = input("Check against breached database? (y/n): ").strip().lower()
    check_pwned = choice == "y"

    tester = PasswordStrengthTester(check_pwned=check_pwned)

    analysis = tester.evaluate_password(password)

    pwned_count = None
    if check_pwned:
        print("\nChecking breach database...")
        pwned_count = tester.check_haveibeenpwned(password)

    tester.display_results(analysis, pwned_count)


if __name__ == "__main__":
    main()
