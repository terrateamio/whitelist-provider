package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: whitelist-provider <allowed_provider1,allowed_provider2,...> [directory]\n")
		fmt.Fprintf(os.Stderr, "\nProviders can be specified as:\n")
		fmt.Fprintf(os.Stderr, "  - Full source address: registry.terraform.io/hashicorp/aws\n")
		fmt.Fprintf(os.Stderr, "  - Short name (assumes hashicorp namespace): aws\n")
		os.Exit(1)
	}

	allowlist := parseAllowlist(os.Args[1])

	dir := "."
	if len(os.Args) >= 3 {
		dir = os.Args[2]
	}

	disallowed, err := checkProviders(dir, allowlist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	if len(disallowed) > 0 {
		fmt.Fprintf(os.Stderr, "Disallowed providers found:\n")
		for _, p := range disallowed {
			fmt.Fprintf(os.Stderr, "  - %s (in %s)\n", p.provider, p.file)
		}
		os.Exit(1)
	}

	fmt.Println("All providers are allowed.")
}

func parseAllowlist(raw string) map[string]bool {
	allowed := make(map[string]bool)
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		allowed[normalizeProvider(p)] = true
	}
	return allowed
}

// normalizeProvider expands short names like "aws" to "registry.terraform.io/hashicorp/aws"
// and lowercases for case-insensitive matching.
func normalizeProvider(name string) string {
	name = strings.ToLower(name)
	parts := strings.Split(name, "/")
	switch len(parts) {
	case 1:
		return "registry.terraform.io/hashicorp/" + name
	case 2:
		return "registry.terraform.io/" + name
	default:
		return name
	}
}

type violation struct {
	provider string
	file     string
}

type parsedFile struct {
	path string
	file *hcl.File
}

func collectTFFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip symlinks entirely — an attacker could use them to manipulate scanning.
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			name := d.Name()
			if strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tf.json") {
				files = append(files, path)
			}
		}
		return nil
	})
	return files, err
}

func checkProviders(dir string, allowlist map[string]bool) ([]violation, error) {
	files, err := collectTFFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("walking directory %s: %w", dir, err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no .tf or .tf.json files found in %s", dir)
	}

	parser := hclparse.NewParser()
	var parsed []parsedFile

	for _, f := range files {
		var hclFile *hcl.File
		var diags hcl.Diagnostics
		if strings.HasSuffix(f, ".tf.json") {
			hclFile, diags = parser.ParseJSONFile(f)
		} else {
			hclFile, diags = parser.ParseHCLFile(f)
		}
		if diags.HasErrors() {
			return nil, fmt.Errorf("parsing %s: %s", f, diags.Error())
		}
		parsed = append(parsed, parsedFile{path: f, file: hclFile})
	}

	// Pass 1: build a map of local name -> source from required_providers across all files.
	sourceMap := make(map[string]string)
	for _, pf := range parsed {
		for localName, source := range extractRequiredProviders(pf.file.Body) {
			sourceMap[localName] = normalizeProvider(source)
		}
	}

	// Pass 2: collect all provider references with their resolved sources.
	var violations []violation
	seen := make(map[string]bool)

	for _, pf := range parsed {
		providers := extractProviderRefs(pf.file, sourceMap)
		for _, p := range providers {
			if !allowlist[p] {
				key := p + ":" + pf.path
				if !seen[key] {
					seen[key] = true
					violations = append(violations, violation{provider: p, file: pf.path})
				}
			}
		}
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].file != violations[j].file {
			return violations[i].file < violations[j].file
		}
		return violations[i].provider < violations[j].provider
	})

	return violations, nil
}

// extractProviderRefs returns normalized provider source addresses from a file.
// It checks: required_providers sources, provider block labels, and
// resource/data block type prefixes (implicit provider references).
func extractProviderRefs(file *hcl.File, sourceMap map[string]string) []string {
	content, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "terraform"},
			{Type: "provider", LabelNames: []string{"name"}},
			{Type: "resource", LabelNames: []string{"type", "name"}},
			{Type: "data", LabelNames: []string{"type", "name"}},
		},
	})
	if diags.HasErrors() {
		return nil
	}

	seen := make(map[string]bool)
	var providers []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			providers = append(providers, p)
		}
	}

	for _, block := range content.Blocks {
		switch block.Type {
		case "terraform":
			for _, source := range extractRequiredProviders(block.Body.(hcl.Body)) {
				add(normalizeProvider(source))
			}
		case "provider":
			if len(block.Labels) > 0 {
				add(resolveLocalName(block.Labels[0], sourceMap))
			}
		case "resource", "data":
			if len(block.Labels) > 0 {
				localName := providerFromResourceType(block.Labels[0])
				add(resolveLocalName(localName, sourceMap))
			}
		}
	}

	return providers
}

// resolveLocalName resolves a provider local name to its normalized source address.
func resolveLocalName(localName string, sourceMap map[string]string) string {
	if source, ok := sourceMap[localName]; ok {
		return source
	}
	return normalizeProvider(localName)
}

// providerFromResourceType extracts the provider local name from a resource type.
// e.g. "aws_instance" -> "aws", "google_compute_instance" -> "google"
func providerFromResourceType(resourceType string) string {
	if idx := strings.Index(resourceType, "_"); idx > 0 {
		return resourceType[:idx]
	}
	return resourceType
}

// extractRequiredProviders returns a map of local name -> source address string
// from terraform { required_providers { ... } } blocks.
// It recurses into terraform blocks since required_providers is nested inside terraform.
func extractRequiredProviders(body hcl.Body) map[string]string {
	result := make(map[string]string)

	content, _, diags := body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "terraform"},
			{Type: "required_providers"},
		},
	})
	if diags.HasErrors() {
		return result
	}

	for _, block := range content.Blocks {
		switch block.Type {
		case "terraform":
			for k, v := range extractRequiredProviders(block.Body) {
				result[k] = v
			}
		case "required_providers":
			attrs, diags := block.Body.JustAttributes()
			if diags.HasErrors() {
				continue
			}
			for name, attr := range attrs {
				source := extractSourceFromAttr(attr)
				if source != "" {
					result[name] = source
				} else {
					result[name] = name
				}
			}
		}
	}

	return result
}

func extractSourceFromAttr(attr *hcl.Attribute) string {
	val, diags := attr.Expr.Value(nil)
	if diags.HasErrors() {
		return ""
	}

	if val.Type().Equals(cty.String) {
		return val.AsString()
	}

	if val.Type().IsObjectType() {
		sourceVal := val.GetAttr("source")
		if sourceVal.IsKnown() && sourceVal.Type().Equals(cty.String) {
			return sourceVal.AsString()
		}
	}

	return ""
}
