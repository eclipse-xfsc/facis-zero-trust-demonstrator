# Contributing to the FACIS Zero Trust Demonstrator

Thanks for your interest in this project. It is part of
[Eclipse XFSC](https://projects.eclipse.org/projects/technology.xfsc) and follows the Eclipse
Foundation's development process.

## Before your first contribution

You must electronically sign the **Eclipse Contributor Agreement (ECA)**:

- <https://www.eclipse.org/legal/ECA.php>

The ECA records that your contributions comply with the
[Developer Certificate of Origin](https://developercertificate.org/). Having an ECA on file
associated with the email address in the **Author** field of your Git commits satisfies the DCO's
sign-off requirement — so no `Signed-off-by` trailer is needed, but the author email on every
commit **must** match an email on your Eclipse account.

A pull request is checked automatically by the `eclipsefdn/eca` status. If it fails, it names the
commit whose author email is not covered. Fix it with `git commit --amend --reset-author` and force
push rather than adding a new commit.

## Making a change

1. Fork this repository and create a branch from `main`.
2. Keep commits focused. Subject lines are short and imperative.
3. Open a pull request from your fork to `eclipse-xfsc:main`.
4. Make sure CI and the `eclipsefdn/eca` check are green before requesting review.

## Reporting issues

Use the repository's GitHub issue tracker. For anything security-sensitive follow the Eclipse
Foundation's [security policy](https://www.eclipse.org/security/) instead — do not open a public
issue.

## Releases

Releases are cut from `main` and tagged. Published releases trigger the SBOM and Eclipse Dash
licence workflows; see [docs/ci-cd.md](docs/ci-cd.md).

## Eclipse Project Handbook

The project follows the [Eclipse Foundation Project Handbook](https://www.eclipse.org/projects/handbook/):

- **Contributions** need an ECA on the commit author's email (above).
- **Intellectual property.** Third-party content goes through Eclipse IP due diligence before it is
  merged: the Eclipse Dash licence gate runs on every pull request, and what it cannot clear is
  sent to the Eclipse IP team. A component the requirements prescribe under a licence that is not
  Apache-2.0-compatible is declared to the client first ([Licenses](docs/licenses.md)).
- **Licence.** Apache-2.0, in `LICENSE` at the root.
- **Security issues** are reported through the Eclipse security policy, never as public issues.
- **Documentation** lives in this repository (`docs/` and `README.md`) and is published to GitHub
  Pages from `main`; the FAP Partner Onboarding repositories are the reference for its structure.
- **Conduct** follows the Eclipse Community Code of Conduct.

## Code of conduct

This project follows the [Eclipse Community Code of Conduct](CODE_OF_CONDUCT.md).

## Contact

Eclipse XFSC developer list: <https://accounts.eclipse.org/mailing-list/xfsc-dev>
