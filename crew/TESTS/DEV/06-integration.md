# 06 Integration — DEV checks

The pre-commit hook and `--staged` are covered by automated tests (including a real subprocess run in a temp repo). Only `action.yml` needs a real GitHub runner.

- [ ] 🖱️ On a test repo, a workflow using `uses: Nakken13/secrety@<ref>` with a committed fake secret fails the job (exit 1) and prints a masked report
- [ ] 🖱️ Same workflow with `sarif: "true"` and `security-events: write`: alerts appear in the Security tab (Code scanning)
- [ ] 🖱️ Same workflow with `exit-zero: "true"`: the job passes and the SARIF is still uploaded
- [ ] 🖱️ `pre-commit run secrety` in a repo wired to the hook blocks a commit that stages a fake secret
