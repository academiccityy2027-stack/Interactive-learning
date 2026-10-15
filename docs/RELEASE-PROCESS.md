# GitHub-to-Cloudflare release process

## Safety rules

- Never experiment or edit code directly in the live Cloudflare Worker.
- Make one focused change on a separate branch and open a pull request to `main`.
- Do not merge until the pull request diff is reviewed and the required **Sign-in regression** check passes.
- Do not deploy merely because a pull request was merged. Production deployment is a separate manual workflow and must receive production-environment approval.
- Never include unrelated changes with a feature or fix.
- Keep a known-good Cloudflare Worker version available for rollback.

## Required one-time GitHub settings

Repository rules and environment reviewers cannot be enforced by workflow YAML alone. Configure them in GitHub before enabling production releases:

1. Open **Settings → Rules → Rulesets** (or **Branches** if using classic protection) for `main`.
2. Require a pull request before merging.
3. Require the **Sign-in regression** status check.
4. Require approval of the pull request and dismiss stale approvals after new commits.
5. Block force pushes and branch deletion; do not allow routine bypasses.
6. Under **Settings → Environments**, create `production` and require a designated reviewer before deployment.
7. Add repository Actions secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. Use a narrowly scoped Cloudflare token with permission to deploy the intended Worker only.
8. Keep the repository variable `PRODUCTION_RELEASES_ENABLED` unset or set to `false` until the currently working production version has been reconciled with the GitHub source and the deployment configuration has been reviewed.

## Pull request checks

The `Sign-in regression` workflow runs for pull requests into `main` and for pushes to `main`. It checks Worker JavaScript syntax and verifies the sign-in contract in `index.js`: the gate can be opened, the form and username/password controls exist, submission calls the login API, and error feedback remains available.

These are source-contract regression checks, not a complete browser-based authentication test. They do not log into production or test real credentials. Add an isolated preview-environment browser test when a safe test account and non-production database are available.

## Approved production release

1. Review the pull request and its full diff.
2. Confirm all required checks pass, especially **Sign-in regression**.
3. Merge only after approval.
4. Only when the GitHub source and Cloudflare deployment config have been reconciled, set `PRODUCTION_RELEASES_ENABLED=true`.
5. From the `main` branch, manually run **Manual Cloudflare production release** and enter exactly `RELEASE`.
6. Confirm the mandatory regression preflight passes.
7. Approve the `production` environment deployment request.
8. Verify the live sign-in page and authentication with an authorized test account, then check the relevant dashboards.
9. If verification fails, stop further releases and roll back to the last known-good Worker version.

## Important current limitation

Cloudflare's known-good sign-in baseline is Worker version **#75**. The GitHub source and Cloudflare's active code have not yet been independently proven identical. Therefore the production release workflow is deliberately disabled unless `PRODUCTION_RELEASES_ENABLED=true`. Do not enable it until that source reconciliation is reviewed. This safety setup must not itself deploy or change the live Worker.
