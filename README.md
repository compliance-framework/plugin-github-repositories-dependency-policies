# Policies for use in the Github Repositories plugin

## Testing

```shell
opa test policies
```

## Bundling

Policies are built into bundle to make distribution easier.

You can easily build the policies by running

```shell
make build
```

## Writing policies.

Policies are written in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language.

```rego
package compliance-framework.license_agpl_v3

violation[] {
	input.settings.license.spdx_id != "AGPL-3.0"
}

title := "Repository is licenced with AGPL v3.0"
description := "Licensing your open source software is essential to clearly communicate the terms under which others can use, modify, and distribute your code. It helps protect your rights as an author, ensures compliance with legal requirements, and fosters trust and collaboration within the open source community. A well-defined license also prevents misuse and clarifies responsibilities for contributors and users."
```
