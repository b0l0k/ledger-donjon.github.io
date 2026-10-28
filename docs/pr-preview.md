# Pull-request previews

The preview build and publication must run on separate runners. Pull-request checkout, dependency installation and site generation are untrusted execution. They must not receive a preview write token or a privileged environment.

Publication must use trusted default-branch code. Build artifacts remain untrusted data: validate the source repository, workflow, exact run, attempt, pull request and source revision before accepting them. Reject stale builds and closed pull requests. Validate archive paths and file types without extracting or executing archive content.

The intended publication credential is a GitHub App installation token restricted to the preview repository with Contents write permission. Maintainers must configure the App installation and the named workflow inputs before publication can work. The configuration is not established by this document or by source inspection alone.

Generated HTML and JavaScript can execute in a visitor's browser. Runner isolation does not sanitize the preview site or establish a safe browser origin.
