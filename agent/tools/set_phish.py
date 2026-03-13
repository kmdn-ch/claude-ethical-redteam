def run(target: str, scenario: str = "phishing_email") -> str:
    template = f"""[TEMPLATE SOCIAL ENGINEERING – DO NOT SEND WITHOUT PERMISSION]
Cible : {target}
Scénario : {scenario}

Topic : Emergency - Security Update {target}

Hello,

We have detected a critical vulnerability in your {target} account.
Click here to verify: https://testphp.vulnweb.com/secure-update (test link only)

Best regards,
The Phantom Security Team
"""
    return template

TOOL_SPEC = {
    "name": "generate_phish_template",
    "description": "Generate a social engineering template for educatinal prupose (no real send)",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "scenario": {"type": "string", "default": "phishing_email"}
        },
        "required": ["target"]
    }
}
