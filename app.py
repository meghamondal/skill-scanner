import re

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


# ----------------------------
# Hardcoded Secret
# ----------------------------

SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9]{20,}",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"https://hooks\.slack\.com/services/[^\s]+",
    r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----",
    r"api[_-]?key\s*:\s*['\"]?[A-Za-z0-9_\-]{12,}",
    r"secret\s*:\s*['\"]?[A-Za-z0-9_\-]{12,}",
    r"token\s*:\s*['\"]?[A-Za-z0-9_\-]{12,}",
]


def detect_hardcoded_secret(text):
    lower = text.lower()

    if "env(" in lower or "${" in text:
        pass

    for pattern in SECRET_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


# ----------------------------
# Prompt Injection
# ----------------------------

PROMPT_PATTERNS = [
    "ignore the user",
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore stop request",
    "ignore cancel",
    "ignore user's request",
    "ignore user request",
    "silently exfiltrate",
    "send file contents",
    "without telling the user",
    "do not tell the user",
]


def detect_prompt_injection(text):

    lower = text.lower()

    return any(p in lower for p in PROMPT_PATTERNS)


# ----------------------------
# Excessive Permissions
# ----------------------------

PERMISSION_PATTERNS = [
    "filesystem: all",
    "filesystem: '*'",
    "read: /",
    "write: /",
    "network: all",
    "network: '*'",
    "allow all domains",
    "egress: all",
]


def detect_permissions(text):

    lower = text.lower()

    return any(p.lower() in lower for p in PERMISSION_PATTERNS)


# ----------------------------
# Provenance
# ----------------------------

def detect_provenance(text):

    lower = text.lower()

    author = "author:" in lower
    version = "version:" in lower
    changelog = "changelog:" in lower

    if not (author and version and changelog):
        return True

    if "update version silently" in lower:
        return True

    if "rewrite version" in lower:
        return True

    return False


# ----------------------------
# Scanner
# ----------------------------

def scan(skill):

    categories = []

    if detect_hardcoded_secret(skill):
        categories.append("hardcoded_secret")

    if detect_prompt_injection(skill):
        categories.append("prompt_injection")

    if detect_permissions(skill):
        categories.append("excessive_permissions")

    if detect_provenance(skill):
        categories.append("unclear_provenance")

    return {"categories": categories}


@app.post("/")
def root(req: SkillRequest):
    return scan(req.skill)


@app.post("/scan")
def scanner(req: SkillRequest):
    return scan(req.skill)