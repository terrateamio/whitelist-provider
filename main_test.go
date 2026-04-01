package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckProviders(t *testing.T) {
	tests := []struct {
		name      string
		allowlist string
		files     map[string]string // path relative to tmpdir -> content
		wantErr   bool
		wantN     int // expected number of violations
		wantProv  []string
	}{
		{
			name:      "required_providers allowed",
			allowlist: "aws",
			files: map[string]string{
				"main.tf": `
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
`,
			},
			wantN: 0,
		},
		{
			name:      "required_providers disallowed",
			allowlist: "aws",
			files: map[string]string{
				"main.tf": `
terraform {
  required_providers {
    evil = {
      source  = "evil-corp/evil"
      version = "~> 1.0"
    }
  }
}
`,
			},
			wantN:    1,
			wantProv: []string{"registry.terraform.io/evil-corp/evil"},
		},
		{
			name:      "provider block resolved via required_providers",
			allowlist: "DataDog/datadog",
			files: map[string]string{
				"versions.tf": `
terraform {
  required_providers {
    datadog = {
      source = "DataDog/datadog"
    }
  }
}
`,
				"main.tf": `
provider "datadog" {
  api_key = "xxx"
}
`,
			},
			wantN: 0,
		},
		{
			name:      "implicit provider from resource block",
			allowlist: "aws",
			files: map[string]string{
				"main.tf": `
resource "evil_instance" "backdoor" {
  name = "pwned"
}
`,
			},
			wantN:    1,
			wantProv: []string{"registry.terraform.io/hashicorp/evil"},
		},
		{
			name:      "implicit provider from data block",
			allowlist: "aws",
			files: map[string]string{
				"main.tf": `
data "evil_secret" "creds" {
  name = "admin"
}
`,
			},
			wantN:    1,
			wantProv: []string{"registry.terraform.io/hashicorp/evil"},
		},
		{
			name:      "implicit provider resolved via required_providers",
			allowlist: "DataDog/datadog",
			files: map[string]string{
				"versions.tf": `
terraform {
  required_providers {
    datadog = {
      source = "DataDog/datadog"
    }
  }
}
`,
				"main.tf": `
resource "datadog_monitor" "cpu" {
  name = "CPU high"
}
`,
			},
			wantN: 0,
		},
		{
			name:      "tf.json file with provider",
			allowlist: "aws",
			files: map[string]string{
				"main.tf.json": `{
  "terraform": {
    "required_providers": {
      "evil": {
        "source": "evil-corp/evil",
        "version": "~> 1.0"
      }
    }
  }
}`,
			},
			wantN:    1,
			wantProv: []string{"registry.terraform.io/evil-corp/evil"},
		},
		{
			name:      "tf.json resource implicit provider",
			allowlist: "aws",
			files: map[string]string{
				"main.tf.json": `{
  "resource": {
    "evil_instance": {
      "backdoor": {
        "name": "pwned"
      }
    }
  }
}`,
			},
			wantN:    1,
			wantProv: []string{"registry.terraform.io/hashicorp/evil"},
		},
		{
			name:      "deeply nested module",
			allowlist: "aws",
			files: map[string]string{
				"main.tf": `resource "aws_instance" "web" {}`,
				"modules/network/sub/main.tf": `
resource "backdoor_shell" "reverse" {
  target = "attacker.com"
}
`,
			},
			wantN:    1,
			wantProv: []string{"registry.terraform.io/hashicorp/backdoor"},
		},
		{
			name:      "case insensitive matching",
			allowlist: "DATADOG/DATADOG",
			files: map[string]string{
				"main.tf": `
terraform {
  required_providers {
    datadog = {
      source = "DataDog/datadog"
    }
  }
}
`,
			},
			wantN: 0,
		},
		{
			name:      "mixed allowed and disallowed",
			allowlist: "aws,google",
			files: map[string]string{
				"main.tf": `
resource "aws_instance" "web" {}
resource "google_compute_instance" "vm" {}
resource "evil_instance" "backdoor" {}
`,
			},
			wantN:    1,
			wantProv: []string{"registry.terraform.io/hashicorp/evil"},
		},
		{
			name:      "no tf files",
			allowlist: "aws",
			files:     map[string]string{},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tt.files {
				writeFile(t, dir, name, content)
			}

			allowlist := parseAllowlist(tt.allowlist)
			violations, err := checkProviders(dir, allowlist)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(violations) != tt.wantN {
				t.Errorf("got %d violations, want %d: %v", len(violations), tt.wantN, violations)
			}

			if tt.wantProv != nil {
				got := make(map[string]bool)
				for _, v := range violations {
					got[v.provider] = true
				}
				for _, want := range tt.wantProv {
					if !got[want] {
						t.Errorf("expected violation for provider %s, not found in %v", want, violations)
					}
				}
			}
		})
	}
}

func TestCheckProviders_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.tf", `resource "aws_instance" "web" {}`)

	// Create a symlinked .tf file with a disallowed provider
	evilDir := t.TempDir()
	writeFile(t, evilDir, "evil.tf", `resource "evil_instance" "x" {}`)
	os.Symlink(filepath.Join(evilDir, "evil.tf"), filepath.Join(dir, "evil.tf"))

	allowlist := parseAllowlist("aws")
	violations, err := checkProviders(dir, allowlist)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, v := range violations {
		if v.provider == "registry.terraform.io/hashicorp/evil" {
			t.Error("symlinked evil.tf should have been skipped")
		}
	}
}

func TestNormalizeProvider(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"aws", "registry.terraform.io/hashicorp/aws"},
		{"DataDog/datadog", "registry.terraform.io/datadog/datadog"},
		{"registry.terraform.io/hashicorp/aws", "registry.terraform.io/hashicorp/aws"},
		{"AWS", "registry.terraform.io/hashicorp/aws"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeProvider(tt.input)
			if got != tt.want {
				t.Errorf("normalizeProvider(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestProviderFromResourceType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"aws_instance", "aws"},
		{"google_compute_instance", "google"},
		{"null_resource", "null"},
		{"singleword", "singleword"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := providerFromResourceType(tt.input)
			if got != tt.want {
				t.Errorf("providerFromResourceType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
