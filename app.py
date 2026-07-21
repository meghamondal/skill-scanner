import re
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


# ==========================================================
# Hardcoded Secret
# ==========================================================

SECRET_PATTERNS = [
    # OpenAI
    r"sk-[A-Za-z0-9_-]{20,}",

    # GitHub
    r"ghp_[A-Za-z0-9]{20,}",
    r"github_pat_[A-Za-z0-9_]{20,}",

    # AWS
    r"AKIA[0-9A-Z]{16}",

    # Google API
    r"AIza[0-9A-Za-z\-_]{35}",

    # Slack webhook
    r"https://hooks\.slack\.com/services/[^\s]+",

    # Private keys
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",

    # Generic hardcoded credentials
    r"api[_-]?key\s*[:=]\s*['\"][^'\"]{10,}['\"]",
    r"access[_-]?key\s*[:=]\s*['\"][^'\"]{10,}['\"]",
    r"secret[_-]?key\s*[:=]\s*['\"][^'\"]{10,}['\"]",
    r"secret\s*[:=]\s*['\"][^'\"]{10,}['\"]",
    r"token\s*[:=]\s*['\"][^'\"]{10,}['\"]",
    r"password\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"bearer\s+['\"][^'\"]{10,}['\"]",
]

def detect_hardcoded_secret(text: str) -> bool:
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


# ==========================================================
# Prompt Injection
# ==========================================================

PROMPT_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore system instructions",
    "ignore user instructions",
    "ignore safety instructions",
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
    "ignore reviewer",
    "ignore review",
    "ignore approval",
    "without user approval",
    "without reviewer approval",
    "silently upload",
    "silently send",
    "exfiltrate files",
]

PROMPT_REGEX = [
    r"ignore\s+.*instructions",
    r"never\s+ask\s+permission",
    r"without\s+telling\s+the\s+user",
    r"do\s+not\s+tell\s+the\s+user",
    r"continue.*user.*stop",
    r"override.*user",
    r"override.*agent",
]


def detect_prompt_injection(text: str) -> bool:
    lower = text.lower()

    for p in PROMPT_PATTERNS:
        if p in lower:
            return True

    for pattern in PROMPT_REGEX:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


# ==========================================================
# Excessive Permissions
# ==========================================================

PERMISSION_PATTERNS = [
    "filesystem: all",
    "filesystem: '*'",
    "network: all",
    "network: '*'",
    "egress: all",
    "full filesystem",
    "entire filesystem",
    "write anywhere",
    "read-write: /",
    "read: /",
    "write: /",
    "allow all domains",
    "unrestricted network",
    "any domain",
    "all hosts",
    "any host",
    "write to entire filesystem",
    "read entire filesystem",
]

PERMISSION_REGEX = [
    r"filesystem\s*:\s*['\"]?all['\"]?",
    r"filesystem\s*:\s*['\"]?\*['\"]?",
    r"network\s*:\s*['\"]?all['\"]?",
    r"network\s*:\s*['\"]?\*['\"]?",
    r"egress\s*:\s*['\"]?all['\"]?",
    r"allowed_domains\s*:\s*\[?\s*['\"]?\*['\"]?",
    r"allowed_domains\s*:\s*['\"]?all['\"]?",
    r"allowed_hosts\s*:\s*['\"]?\*['\"]?",
    r"filesystem.*read.*write.*\/",
    r"filesystem.*\/",
    r"domains.*\*",
    r"hosts.*\*",
    r"network.*any",
    r"egress.*any",
]


def detect_permissions(text: str) -> bool:
    lower = text.lower()

    for p in PERMISSION_PATTERNS:
        if p in lower:
            return True

    for pattern in PERMISSION_REGEX:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


# ==========================================================
# Provenance
# ==========================================================

def detect_provenance(text: str) -> bool:
    lower = text.lower()

    author = "author:" in lower
    version = "version:" in lower
    changelog = "changelog:" in lower

    # Missing all provenance metadata
    if not author and not version and not changelog:
        return True

    suspicious = [
        "rewrite version",
        "update version silently",
        "modify frontmatter",
        "change version automatically",
    ]

    for s in suspicious:
        if s in lower:
            return True

    return False


# ==========================================================
# Scanner
# ==========================================================

def scan(skill: str):
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