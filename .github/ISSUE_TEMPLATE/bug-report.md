---
name: Bug report
about: Create a report to help us improve
title: "[BUG]"
labels: bug
assignees: ""
---

Thanks for submitting a bug report to help us improve.

If you have a support question about how to use the module, no one is monitoring the issues to answer those. Consider posting on StackOverflow instead using the "passport-saml" tag or using [GitHub Discussions](https://github.com/node-saml/passport-saml/discussions).

If you are upgrading to a new version, particularlly if you are upgrading to a new `semver-major` version, please be sure the problem isn't a configuration issue. All our `semver-major` changes involve breaking change. So, if you are upgrading to a new `semver-major` version, make sure you've carefully read over the CHANGELOG to make sure that your problem isn't a problem with configuration or an API change.

After you've read the CHANGELOG, please look at the [Wiki](https://github.com/node-saml/passport-saml/wiki) to see if you're issue has been address.

After you've read the CHANGELOG and checked the Wiki, please search through issues, including close issues to see if you're issue has already been addressed. We find that most "bugs" that are configuration issues that have already been address in closed issues via this link (https://github.com/node-saml/passport-saml/issues?q=is%3Aissue).

## Spec-driven development

This project is focused on compliance with the SAML 2.0 specification. For any bug report that
involves the SAML spec, please link to the related parts of the spec and quote the passages too.

Start here: <http://saml.xml.org/saml-specifications>

You might also check the spec to confirm that it doesn't address your particular bug and mention
that you found no references in the spec concerning your issue.

## Community development model

`passport-saml` is maintained by a number of current users. There is no author or primary maintainer
waiting to write your tests and documentation for you. To increase the odds that your issue
is promptly dealt with, consider a pull request to address the issue that includes test coverage
and updated documentation.

### To Reproduce

Steps to reproduce the behavior. Ideally, expressed through an automated test.

### Expected behavior

A clear and concise description of what you expected to happen.

### Environment

- Node.js version:
- `passport-saml` version:
