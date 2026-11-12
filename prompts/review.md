# Review contract

Supply the task specification, base commit, diff, relevant surrounding code, interfaces, and test results.

Check:

1. Correctness against the specification and edge cases.
2. Regressions in existing behavior.
3. Security-relevant mistakes.
4. Test adequacy: would the tests fail if the change were wrong?

Return exactly one verdict on the first line:

- `APPROVED`
- `CHANGES_REQUESTED`
- `INCONCLUSIVE`

Then list findings with file:line references and one actionable fix each. Review approval is not deployment or engagement authorization.
