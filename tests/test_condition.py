"""Condition parsing: which selections a rule actually requires."""

import pytest

from dca.rules.condition import ConditionError, _expand_of, parse_condition


def branches(condition, selections):
    result = parse_condition(condition, selections)
    return result.exact, sorted(sorted(b) for b in result.branches)


def test_single_selection():
    assert branches("selection", ["selection"]) == (True, [["selection"]])


def test_and_requires_both():
    assert branches("a and b", ["a", "b"]) == (True, [["a", "b"]])


def test_or_gives_two_branches():
    exact, got = branches("a or b", ["a", "b"])
    assert exact
    assert got == [["a"], ["b"]]


def test_not_selection_is_a_filter_and_requires_nothing():
    """A negated selection is a filter. Its fields need not be present for the
    rule to fire, so it must not make the rule look blind."""
    assert branches("selection and not filter", ["selection", "filter"]) == (True, [["selection"]])


def test_parentheses_distribute_over_and():
    exact, got = branches("(a or b) and c", ["a", "b", "c"])
    assert exact
    assert got == [["a", "c"], ["b", "c"]]


def test_nested_parentheses():
    exact, got = branches("((a or b) and c) or d", ["a", "b", "c", "d"])
    assert exact
    assert got == [["a", "c"], ["b", "c"], ["d"]]


def test_one_of_them_is_one_branch_per_selection():
    exact, got = branches("1 of them", ["a", "b", "c"])
    assert exact
    assert got == [["a"], ["b"], ["c"]]


def test_all_of_them_is_a_single_branch():
    assert branches("all of them", ["a", "b"]) == (True, [["a", "b"]])


def test_one_of_a_wildcard_matches_only_that_prefix():
    exact, got = branches("1 of selection_*", ["selection_a", "selection_b", "filter"])
    assert exact
    assert got == [["selection_a"], ["selection_b"]]


def test_n_of_greater_than_one_requires_all_the_safe_direction():
    """Which N of M is not knowable statically, so require all of them. That
    over reports blindness, which is the direction the tool is allowed to err."""
    assert branches("2 of selection_*", ["selection_a", "selection_b"]) == (
        True, [["selection_a", "selection_b"]]
    )


def test_aggregation_tail_after_a_pipe_is_ignored():
    """count() changes when a rule fires, not which fields it reads."""
    assert branches("selection | count() by host > 5", ["selection"]) == (True, [["selection"]])


def test_aggregation_tail_with_a_filter():
    assert branches(
        "selection and not filter | count(dst) by src > 10", ["selection", "filter"]
    ) == (True, [["selection"]])


def test_list_of_conditions_is_an_implicit_or():
    exact, got = branches(["a", "b"], ["a", "b"])
    assert exact
    assert got == [["a"], ["b"]]


def test_duplicate_branches_are_collapsed():
    exact, got = branches("a or a", ["a"])
    assert exact
    assert got == [["a"]]


@pytest.mark.parametrize("condition", ["", None, 42, "nonsense ^^ broken", "a and", "(a or b"])
def test_unparseable_condition_falls_back_to_every_selection(condition):
    """The fallback must require everything, so a parse failure can only ever
    make the audit more pessimistic and never more permissive."""
    exact, got = branches(condition, ["a", "b"])
    assert exact is False
    assert got == [["a", "b"]]


def test_condition_naming_an_unknown_selection_falls_back():
    exact, got = branches("selection and typo", ["selection"])
    assert exact is False
    assert got == [["selection"]]


def test_of_matching_no_selection_falls_back():
    exact, got = branches("1 of nomatch_*", ["a", "b"])
    assert exact is False
    assert got == [["a", "b"]]


def test_required_everywhere_finds_the_common_selections():
    result = parse_condition("(a or b) and c", ["a", "b", "c"])
    assert result.required_everywhere == {"c"}


def test_required_everywhere_is_empty_with_no_overlap():
    result = parse_condition("a or b", ["a", "b"])
    assert result.required_everywhere == frozenset()


def test_expand_of_rejects_an_unreadable_count():
    with pytest.raises(ConditionError, match="cannot read a count"):
        _expand_of("many of them", ["a"])


def test_required_everywhere_with_no_branches():
    from dca.rules.condition import ConditionBranches

    assert ConditionBranches(branches=(), exact=True).required_everywhere == frozenset()


def test_of_naming_an_exact_selection_without_a_wildcard():
    exact, got = branches("1 of selection", ["selection", "other"])
    assert exact
    assert got == [["selection"]]


def test_all_of_an_exact_selection():
    assert branches("all of selection", ["selection", "other"]) == (True, [["selection"]])


def test_list_containing_an_unparseable_entry_falls_back():
    exact, got = branches(["a", "b and"], ["a", "b"])
    assert exact is False
    assert got == [["a", "b"]]


def test_trailing_token_after_a_complete_expression_falls_back():
    exact, got = branches("a b", ["a", "b"])
    assert exact is False
    assert got == [["a", "b"]]


def test_unrecognised_characters_fall_back():
    exact, got = branches("a & b", ["a", "b"])
    assert exact is False
    assert got == [["a", "b"]]


def test_condition_that_is_only_an_aggregation_falls_back():
    exact, got = branches("| count() by host > 5", ["a"])
    assert exact is False
    assert got == [["a"]]


def test_stray_closing_paren_falls_back():
    exact, got = branches("a )", ["a"])
    assert exact is False
    assert got == [["a"]]


def test_condition_starting_with_a_closing_paren_falls_back():
    exact, got = branches(") a", ["a"])
    assert exact is False
    assert got == [["a"]]


def test_empty_selection_list_with_a_named_condition_falls_back():
    exact, got = branches("selection", [])
    assert exact is False
    assert got == [[]]
