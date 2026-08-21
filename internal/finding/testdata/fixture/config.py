# AWS's canonical documentation example keys. Both GitHub and Gitleaks allowlist
# these, which is itself the behaviour worth having in a fixture.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Not a real credential. A high-entropy generic key, deliberately not shaped like
# any provider's token: Gitleaks flags it via `generic-api-key`, and GitHub's push
# protection - which matches known provider patterns - leaves it alone.
SERVICE_API_KEY = "k7Qm2ZxR9vBnT4wLpY8sJdF3hGc6aErU1oNiXbVt"
