#!/usr/bin/env bash
# Replace the GitHub identity placeholder across the repository in one pass.
#
# Every URL in this repository carries __GITHUB_USERNAME__ rather than a real
# account, so the repo can be built before the account is known and then bound
# to it in one commit. Run this once, read the diff, then commit.
#
# Usage:
#   tools/set_identity.sh <github-username>
#
# Also sets the git author identity for future commits in this clone.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <github-username>" >&2
  exit 2
fi

USERNAME="$1"

if [[ ! "$USERNAME" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]]; then
  echo "error: '$USERNAME' is not a valid GitHub username" >&2
  exit 2
fi

cd "$(dirname "$0")/.."

FILES=$(git grep -l '__GITHUB_USERNAME__' || true)
if [[ -z "$FILES" ]]; then
  echo "no placeholders found, identity is already set"
  exit 0
fi

COUNT=$(echo "$FILES" | wc -l | tr -d ' ')
echo "rewriting __GITHUB_USERNAME__ to $USERNAME in $COUNT file(s):"
echo "$FILES" | sed 's/^/  /'

echo "$FILES" | while read -r file; do
  [[ -n "$file" ]] && perl -pi -e "s/__GITHUB_USERNAME__/${USERNAME}/g" "$file"
done

git config user.name "Nilay Dave"
git config user.email "${USERNAME}@users.noreply.github.com"

echo
echo "done. Review with: git diff"
echo "Then commit:       git commit -am 'chore: bind repository urls to the github account'"
