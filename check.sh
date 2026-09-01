#!/usr/bin/env bash
# Everything this project claims about itself, checked in one command.
#
# Nothing here is bespoke: these are the standard tools a reviewer would reach
# for anyway. Missing ones are skipped with a note rather than failing, so the
# script stays useful before you have installed all of them.
#
#   ./check.sh
set -uo pipefail
cd "$(dirname "$0")" || exit 1

# Python tools are usually in a virtualenv rather than on the system PATH.
# Look in the obvious places so they are not silently skipped.
#
# Appended, never prepended, and deliberately so: prepending would let a
# binary named "find", "grep" or "python3" dropped into a venv inside the
# checked-out tree shadow the real one for every command below. These
# directories only fill gaps; the system PATH always wins.
for d in "$PWD/venv/bin" "$HOME/.local/audit/bin" "$HOME/.local/bin"; do
    [ -d "$d" ] && PATH="$PATH:$d"
done
export PATH

fail=0
skipped=0
have() { command -v "$1" >/dev/null 2>&1; }
step() { printf '\n=== %s ===\n' "$1"; }
ok()   { printf '  PASS  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }
# A skipped tool is not a pass. It is counted and reported at the end, because
# a green run that quietly checked half of what it claims is worse than a red one.
skip() { printf '  skip  %s (not installed)\n' "$1"; skipped=$((skipped + 1)); }

step "self-tests"
while IFS= read -r -d '' f; do
    if grep -q -- '--test' "$f"; then
        if out=$(python3 "$f" --test 2>&1); then
            ok "$f"
        else
            bad "$f"
            echo "$out"
        fi
    fi
done < <(find . -name "*.py" -not -path "./venv/*" -print0 | sort -z)

step "ruff (lint, latent bugs, security rules)"
if have ruff; then
    if ruff check .; then ok "ruff"; else bad "ruff"; fi
else
    skip "ruff"
fi

step "bandit (python security)"
if have bandit; then
    if bandit -q -r . -c pyproject.toml >/dev/null 2>&1; then
        ok "bandit"
    else
        bandit -r . -c pyproject.toml 2>/dev/null | tail -20
        bad "bandit"
    fi
else
    skip "bandit"
fi

step "mypy (types)"
if have mypy; then
    if mypy --ignore-missing-imports --no-error-summary . >/dev/null 2>&1; then
        ok "mypy"
    else
        mypy --ignore-missing-imports . 2>&1 | tail -10
        bad "mypy"
    fi
else
    skip "mypy"
fi

step "semgrep (dataflow / security rulesets)"
if have semgrep; then
    n=$(semgrep scan --config=p/python --config=p/security-audit \
          --metrics=off --json . 2>/dev/null \
        | python3 -c "import json,sys;print(len(json.load(sys.stdin).get('results',[])))" \
        2>/dev/null)
    if [ "${n:-x}" = "0" ]; then
        ok "semgrep (0 findings)"
    else
        semgrep scan --config=p/python --config=p/security-audit \
            --metrics=off . 2>/dev/null | tail -20
        bad "semgrep (${n:-error})"
    fi
else
    skip "semgrep"
fi

step "gitleaks (secrets)"
if have gitleaks; then
    if gitleaks detect --no-git --source . --redact >/dev/null 2>&1; then
        ok "gitleaks"
    else
        bad "gitleaks"
    fi
else
    skip "gitleaks"
fi

step "shellcheck"
SH=()
while IFS= read -r -d '' f; do SH+=("$f"); done \
    < <(find . -name "*.sh" -print0 | sort -z)
if [ ${#SH[@]} -eq 0 ]; then
    printf '  none\n'
elif have shellcheck; then
    if shellcheck "${SH[@]}"; then ok "shellcheck"; else bad "shellcheck"; fi
else
    skip "shellcheck"
fi

step "PSScriptAnalyzer"
PS1=()
while IFS= read -r -d '' f; do PS1+=("$f"); done \
    < <(find . -name "*.ps1" -print0 | sort -z)
if [ ${#PS1[@]} -eq 0 ]; then
    printf '  none\n'
elif have pwsh; then
    # PSAvoidUsingWriteHost is excluded on purpose: these are interactive
    # installers whose coloured output is the point of them.
    quoted=$(printf '"%s",' "${PS1[@]}")
    n=$(pwsh -NoProfile -Command \
        "(@(${quoted%,}) | ForEach-Object { Invoke-ScriptAnalyzer -Path \$_ \
          -Severity Error,Warning -ExcludeRule PSAvoidUsingWriteHost }).Count" \
        2>/dev/null)
    if [ "${n:-1}" = "0" ]; then
        ok "PSScriptAnalyzer (0 findings)"
    else
        bad "PSScriptAnalyzer ($n findings)"
    fi
else
    skip "pwsh"
fi

printf '\n'
if [ $fail -ne 0 ]; then
    echo "SOMETHING FAILED"
elif [ $skipped -ne 0 ]; then
    echo "PASSED WHAT RAN - $skipped tool(s) missing, not checked"
else
    echo "ALL CLEAR"
fi
exit $fail
