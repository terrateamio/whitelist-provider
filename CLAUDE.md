# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Terraform provider allowlist checker for Terrateam pre-plan workflows. Parses HCL and validates all provider references against a configurable allowlist. This is a proof of concept, not officially supported.

## Commands

```bash
make build    # build binary
make test     # run all tests
make clean    # remove built binaries
go test -run TestCheckProviders/implicit_provider_from_resource_block ./...  # run a single test
```

## Architecture

Single-binary Go tool (`main.go`) using the HashiCorp HCL v2 parser. The core logic is a two-pass system:

1. **Pass 1**: Walk all `.tf` and `.tf.json` files recursively via `collectTFFiles()`, parse them, then build a `sourceMap` of local provider names to their full source addresses from `required_providers` blocks.

2. **Pass 2**: Extract all provider references from each file via `extractProviderRefs()` using three detection methods:
   - Explicit `required_providers` source attributes
   - `provider` block labels (resolved against the sourceMap)
   - Implicit references from `resource`/`data` block type prefixes (e.g. `aws_instance` → `aws`)

All provider names are normalized to full registry paths (`registry.terraform.io/namespace/name`) and lowercased for case-insensitive comparison.

## Security design decisions

- Symlinks are skipped during directory walking to prevent scan manipulation
- Resource/data block type prefixes are checked to prevent bypass via implicit providers
- `.tf.json` files are parsed to prevent format-based bypass

## Release

GitHub Actions workflow (`.github/workflows/release.yml`) triggers on push to main. Version bump is determined by conventional commit prefixes: `breaking-change`/`feat!` → major, `feat` → minor, else patch.
