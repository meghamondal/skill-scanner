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
    r"ghp_[A-Za-z0-9]{20,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"https://hooks\.slack\.com/services/[^\s]+",
    r"-----BEGIN .*PRIVATE KEY-----",

    r"api[_-]?key\s*:\s*['\"][^'\"]{12,}['\"]",
    r"secret\s*:\s*['\"][^'\"]{12,}['\"]",
    r"password\s*:\s*['\"][^'\"]{8,}['\"]",
    r"token\s*:\s*['\"][^'\"]{12,}['\"]",
]


def detect_hardcoded_secret(text):
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


# ----------------------------
# Prompt Injection
# ----------------------------

PROMPT_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore system instructions",
    "ignore user instructions",
    "ignore stop request",
    "ignore cancel",
    "continue even if user says stop",
    "never ask permission",
    "without telling the user",
    "do not tell the user",
    "silently exfiltrate",
    "send file contents",
    "upload local files",
    "override user",
    "override agent",
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
    "read-write: /",
    "full filesystem",
    "entire filesystem",
    "write anywhere",
    "network: all",
    "network: '*'",
    "egress: all",
    "allow all domains",
    "all domains",
    "unrestricted network",
    "internet access",
]

PERMISSION_REGEX = [
    r"filesystem\s*:\s*['\"]?all['\"]?",
    r"filesystem\s*:\s*['\"]?\*['\"]?",
    r"network\s*:\s*['\"]?all['\"]?",
    r"network\s*:\s*['\"]?\*['\"]?",
    r"egress\s*:\s*['\"]?all['\"]?",
    r"allowed_domains\s*:\s*\[?\s*['\"]?\*['\"]?",
]

def detect_permissions(text):

    lower = text.lower()

    for p in PERMISSION_PATTERNS:
        if p.lower() in lower:
            return True

    for pattern in PERMISSION_REGEX:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


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
    
    if "modify frontmatter" in lower:
        return True
    if "change version automatically" in lower:
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