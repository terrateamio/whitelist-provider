# whitelist-provider

**This is a proof of concept. It is not officially supported by Terrateam and was written on a best-effort basis using [Claude Code](https://claude.ai/code). Use at your own risk.**

A Terraform provider allowlist checker that validates HCL files only reference approved providers. Intended for use as a [Terrateam](https://terrateam.io) pre-plan workflow step to mitigate risk from untrusted HCL.

## Build

```
make build
make test
```

## Usage

```
whitelist-provider <allowed_providers> [directory]
```

Providers can be specified as:
- Short name: `aws` (assumes `hashicorp/aws`)
- Namespace/name: `DataDog/datadog`
- Full source: `registry.terraform.io/hashicorp/aws`

```
whitelist-provider "aws,google,DataDog/datadog" ./terraform
```

Exit codes: `0` = all providers allowed, `1` = disallowed provider found, `2` = error.

## What it checks

- `required_providers` source attributes
- `provider` block labels (resolved against `required_providers`)
- Implicit provider references from `resource` and `data` block type prefixes
- Both `.tf` and `.tf.json` file formats
- All files recursively (symlinks are skipped)
- Case-insensitive source matching

## Terrateam integration

```yaml
workflows:
  - tag_query: ""
    plan:
      - type: run
        cmd:
          - sh
          - -c
          - whitelist-provider "aws,google,DataDog/datadog"
      - type: init
      - type: plan
```

## License

MIT
