"""Temporary test harness -- bypasses PowerShell quoting issues."""
import sys

sys.argv = [
    "sg", "mcs.driver.mail:MailDriver",
    "--kwargs", '{"read_adapter": "gmail", "send_adapter": "gmail", "read_kwargs": {}, "send_kwargs": {}}',
    "--skill-name", "mcs-gmail",
    "--output", "./generated-skill-gmail",
    "--auth-method", "auth0-linkauth",
    "--credential-kwargs", "read_kwargs,send_kwargs",
]
exec(open("scripts/skill_generator.py").read())
