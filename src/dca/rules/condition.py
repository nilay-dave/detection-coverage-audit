"""Work out which selections a Sigma rule's condition actually requires.

Treating every field in every selection as required produces a false positive on
any defensively written rule. This is real content, not a contrived example:

    detection:
      selection_sysmon:
        Image|endswith: '\\powershell.exe'
      selection_4688:
        NewProcessName|endswith: '\\powershell.exe'
      condition: selection_sysmon or selection_4688

On an estate that collects Windows Security EventID 4688, that rule fires
correctly through `selection_4688`. An audit that resolves the union of all
fields calls it blind because `Image` is absent, which is wrong, and wrong in the
direction that makes the tool look careless to the people who write rules well.

This module reduces a condition to a set of alternative branches, where each
branch is the set of selections that must all match for that branch to fire. A
rule is blind only when every branch has a problem.

Scope, stated plainly. Sigma conditions support `and`, `or`, `not`, parentheses,
and the aggregation forms `1 of them`, `all of them`, `1 of selection_*` and
`count() by ... > N`. This parser handles the boolean operators, parentheses and
the `of` forms. It does not interpret aggregation thresholds, because a `count()`
expression changes when a rule fires, not which fields it reads. Anything it
cannot parse falls back to requiring every selection, which is the old
behaviour, so an unparseable condition can only ever make the audit more
pessimistic and never more permissive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# A branch is a set of selection names that must all be present for it to fire.
Branch = frozenset[str]

_TOKEN = re.compile(
    r"""
    \s*(?:
        (?P<lparen>\()
      | (?P<rparen>\))
      | (?P<op>\b(?:and|or|not)\b)
      | (?P<of>\b(?:\d+|all)\s+of\s+(?:them\b|[A-Za-z0-9_]+\*|[A-Za-z0-9_]+\b))
      | (?P<agg>\|.*|\b(?:count|min|max|avg|sum)\s*\([^)]*\).*)
      | (?P<name>[A-Za-z0-9_*]+)
    )\s*
    """,
    re.VERBOSE | re.IGNORECASE,
)


class ConditionError(ValueError):
    """Raised when a condition cannot be reduced to branches."""


@dataclass(frozen=True)
class ConditionBranches:
    """The alternative ways a rule can fire.

    `branches` holds one entry per alternative; each entry is the set of
    selections that must all match. `exact` is False when the parser fell back,
    in which case the single branch is every selection in the rule.
    """

    branches: tuple[Branch, ...]
    exact: bool

    @property
    def required_everywhere(self) -> frozenset[str]:
        """Selections that appear in every branch, so no branch avoids them."""
        if not self.branches:
            return frozenset()
        common = set(self.branches[0])
        for branch in self.branches[1:]:
            common &= branch
        return frozenset(common)


def _expand_of(token: str, selections: list[str]) -> list[list[str]]:
    """Expand `1 of them`, `all of them`, `1 of selection_*` to alternatives.

    Returns a list of alternatives, each a list of selections that must all
    match. `1 of X` becomes one alternative per matching selection; `all of X`
    becomes a single alternative holding all of them.
    """
    head, _, target = token.lower().partition(" of ")
    target = target.strip()

    if target == "them":
        matching = list(selections)
    elif "*" in target:
        pattern = re.compile("^" + re.escape(target).replace(r"\*", ".*") + "$", re.IGNORECASE)
        matching = [s for s in selections if pattern.match(s)]
    else:
        matching = [s for s in selections if s.lower() == target]

    if not matching:
        raise ConditionError(f"'{token}' matches no selection")

    if head.strip() == "all":
        return [matching]
    try:
        count = int(head.strip())
    except ValueError as exc:
        raise ConditionError(f"cannot read a count from '{token}'") from exc
    if count == 1:
        return [[name] for name in matching]
    # N of M with N greater than 1: every selection could be needed, and which
    # ones is not knowable statically. Require all of them, the safe direction.
    return [matching]


def parse_condition(condition: object, selections: list[str]) -> ConditionBranches:
    """Reduce a Sigma condition to alternative branches of required selections."""
    fallback = ConditionBranches(branches=(frozenset(selections),), exact=False)

    if isinstance(condition, list):
        # A list of conditions is an implicit OR in Sigma.
        collected: list[Branch] = []
        for item in condition:
            parsed = parse_condition(item, selections)
            if not parsed.exact:
                return fallback
            collected.extend(parsed.branches)
        return ConditionBranches(branches=tuple(dict.fromkeys(collected)), exact=True)

    if not isinstance(condition, str) or not condition.strip():
        return fallback

    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(condition):
        match = _TOKEN.match(condition, position)
        if not match or match.end() == position:
            return fallback
        kind = match.lastgroup
        if kind == "agg":
            # An aggregation tail, introduced by a pipe or an aggregation
            # function, changes when a rule fires rather than which fields it
            # reads. Everything before it has already been tokenized, so stop
            # here and keep what the boolean part gave us.
            break
        tokens.append((kind, match.group(kind)))
        position = match.end()

    if not tokens:
        return fallback

    try:
        branches, index = _parse_or(tokens, 0, selections)
    except ConditionError:
        return fallback
    if index != len(tokens):
        # Tokens left over means the expression did not consume cleanly, for
        # example "a b" with no operator between them.
        return fallback
    # _parse_or always yields at least one branch, since _parse_atom either
    # returns a single branch or raises, so there is no empty case to guard.
    return ConditionBranches(branches=tuple(dict.fromkeys(branches)), exact=True)


def _parse_or(tokens, index, selections) -> tuple[list[Branch], int]:
    branches, index = _parse_and(tokens, index, selections)
    while index < len(tokens) and tokens[index][0] == "op" and tokens[index][1].lower() == "or":
        right, index = _parse_and(tokens, index + 1, selections)
        branches = branches + right
    return branches, index


def _parse_and(tokens, index, selections) -> tuple[list[Branch], int]:
    branches, index = _parse_atom(tokens, index, selections)
    while index < len(tokens) and tokens[index][0] == "op" and tokens[index][1].lower() == "and":
        right, index = _parse_atom(tokens, index + 1, selections)
        # AND distributes over the alternatives on each side.
        branches = [left | other for left in branches for other in right]
    return branches, index


def _parse_atom(tokens, index, selections) -> tuple[list[Branch], int]:
    if index >= len(tokens):
        raise ConditionError("condition ends unexpectedly")

    kind, value = tokens[index]

    if kind == "op" and value.lower() == "not":
        # A negated selection is a filter. Its fields do not have to be present
        # for the rule to fire, so it contributes nothing to a branch.
        _, index = _parse_atom(tokens, index + 1, selections)
        return [frozenset()], index

    if kind == "lparen":
        branches, index = _parse_or(tokens, index + 1, selections)
        if index >= len(tokens) or tokens[index][0] != "rparen":
            raise ConditionError("unbalanced parentheses")
        return branches, index + 1

    if kind == "of":
        alternatives = _expand_of(value, selections)
        return [frozenset(alternative) for alternative in alternatives], index + 1

    if kind == "name":
        if value not in selections:
            raise ConditionError(f"condition names '{value}', which is not a selection")
        return [frozenset({value})], index + 1

    raise ConditionError(f"unexpected token {value!r}")
