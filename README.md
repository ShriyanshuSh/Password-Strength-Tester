🔐 Password Strength Tester:
A Python-based password security analysis tool that evaluates password strength using entropy-based scoring and checks exposure against real-world breach databases.
Built with the zxcvbn library and integrated with the Have I Been Pwned API using a secure k-anonymity model.

🚀 Features:
🔎 Password strength evaluation using pattern recognition and entropy analysis
📊 Strength score classification (Very Weak → Very Strong)
⏱ Estimated offline crack time simulation
💡 Actionable feedback and improvement suggestions
🛡 Optional breach detection via Have I Been Pwned API
🔐 Secure SHA-1 k-anonymity implementation (passwords never sent in plaintext)
🖥 Simple CLI interface for accessibility

🛠 Technologies Used:
Python 3
zxcvbn
requests
Have I Been Pwned Passwords API
