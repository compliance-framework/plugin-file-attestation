package main

import (
	"path/filepath"
	"testing"
)

func TestResolveTrackedPathLabels(t *testing.T) {
	relativePath, err := filepath.Abs("configs/app.yaml")
	if err != nil {
		t.Fatalf("resolve relative path: %v", err)
	}

	tests := []struct {
		name       string
		path       string
		wantSource string
		wantHost   string
		wantFile   string
	}{
		{
			name:       "relative path is local file",
			path:       "configs/app.yaml",
			wantSource: "local",
			wantHost:   "host-a",
			wantFile:   relativePath,
		},
		{
			name:       "file uri is local file",
			path:       "file:///etc/myapp/config.yaml",
			wantSource: "local",
			wantHost:   "host-a",
			wantFile:   "/etc/myapp/config.yaml",
		},
		{
			name:       "http uri is remote",
			path:       "https://example.com/config.yaml",
			wantSource: "remote",
			wantHost:   "example.com",
			wantFile:   "config.yaml",
		},
		{
			name:       "oci uri is remote",
			path:       "oci://registry.example.com/repo/artifact",
			wantSource: "remote",
			wantHost:   "registry.example.com",
			wantFile:   "repo/artifact",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveTrackedPathLabels(tt.path, "host-a")
			if got.Source != tt.wantSource {
				t.Fatalf("source mismatch: got %q want %q", got.Source, tt.wantSource)
			}
			if got.Host != tt.wantHost {
				t.Fatalf("host mismatch: got %q want %q", got.Host, tt.wantHost)
			}
			if got.File != tt.wantFile {
				t.Fatalf("file mismatch: got %q want %q", got.File, tt.wantFile)
			}
		})
	}
}

func TestBuildEvidenceLabelsForLocalPath(t *testing.T) {
	relativePath, err := filepath.Abs("configs/app.yaml")
	if err != nil {
		t.Fatalf("resolve relative path: %v", err)
	}

	labels := buildEvidenceLabels("configs/app.yaml", map[string]string{
		"team": "platform",
	}, "host-a")

	if labels["provider"] != "file" {
		t.Fatalf("unexpected provider label: %q", labels["provider"])
	}
	if labels["type"] != "attestation" {
		t.Fatalf("unexpected type label: %q", labels["type"])
	}
	if labels["source"] != "local" {
		t.Fatalf("unexpected source label: %q", labels["source"])
	}
	if labels["host"] != "host-a" {
		t.Fatalf("unexpected host label: %q", labels["host"])
	}
	if labels["file"] != relativePath {
		t.Fatalf("unexpected file label: %q", labels["file"])
	}
	if labels["team"] != "platform" {
		t.Fatalf("expected policy label to be preserved, got %q", labels["team"])
	}
}

func TestBuildEvidenceLabelsForRemotePath(t *testing.T) {
	labels := buildEvidenceLabels("https://example.com/path/to/config.yaml", nil, "host-a")

	if labels["source"] != "remote" {
		t.Fatalf("unexpected source label: %q", labels["source"])
	}
	if labels["host"] != "example.com" {
		t.Fatalf("unexpected host label: %q", labels["host"])
	}
	if labels["file"] != "path/to/config.yaml" {
		t.Fatalf("unexpected file label: %q", labels["file"])
	}
}
