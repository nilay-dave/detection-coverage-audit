# Audit the HTML report for accessibility
labels: enhancement,good first issue

The report is read by analysts and leads, sometimes projected in a review. It has
a light and dark theme and semantic table markup, and it has never been checked
properly.

## What to do

- Verify contrast ratios for both themes against WCAG AA, particularly the verdict colours, which are the one place colour carries meaning.
- Give the verdict column a text label as well as a colour, so it does not depend on colour alone. It currently does carry text, so confirm and keep it that way.
- Add a `<caption>` to the findings table and a skip link past the summary tiles.
- Check keyboard navigation and screen reader output on the chip list.

## Why this is a good first issue

It is self contained in one Jinja template and one CSS block, needs no
understanding of the audit logic, and `tests/test_report.py` already shows how to
assert on rendered output.
