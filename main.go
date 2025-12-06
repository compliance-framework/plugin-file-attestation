package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
)

type Validator interface {
	Validate() error
}

type PluginConfig struct {
	FilePath        string `mapstructure:"file_path"`
	AttestationPath string `mapstructure:"attestation_path"`
	// Comma-separated list of authorized signers
	AuthorizedSigners string `mapstructure:"authorized_signers"`
	// Authentication for URI-like sources
	BasicAuthUsername string `mapstructure:"basic_auth_username"`
	BasicAuthPassword string `mapstructure:"basic_auth_password"`
	BearerToken       string `mapstructure:"bearer_token"`
}

// FileSignerRule defines a file path and its authorized signers for attestation verification
type FileSignerRule struct {
	Path              string   `json:"path"`
	AttestationPath   string   `json:"attestation_path"`
	AuthorizedSigners []string `json:"authorized_signers"`
}

// ParsedConfig holds the parsed JSON configuration fields
type ParsedConfig struct {
	FilePath          string   `mapstructure:"path"`
	AttestationPath   string   `mapstructure:"attestation_path"`
	AuthorizedSigners []string `mapstructure:"authorized_signers"`
	// Authentication for URI-like sources
	BasicAuthUsername string `mapstructure:"basic_auth_username"`
	BasicAuthPassword string `mapstructure:"basic_auth_password"`
	BearerToken       string `mapstructure:"bearer_token"`
}

func parseFilePath(filePath string) (string, error) {
	parsed, err := url.Parse(filePath)
	if err != nil {
		return "", fmt.Errorf("invalid file path: %w", err)
	}
	if parsed.Scheme == "" {
		return "file://" + filePath, nil
	}
	return filePath, nil
}

// Parse converts the flat PluginConfig into a ParsedConfig, expanding the
// comma-separated list of authorized signers into a slice.
func (c *PluginConfig) Parse() (*ParsedConfig, error) {
	var err error
	c.FilePath, err = parseFilePath(c.FilePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}
	c.AttestationPath, err = parseFilePath(c.AttestationPath)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation path: %w", err)
	}
	parsed := &ParsedConfig{
		FilePath:        c.FilePath,
		AttestationPath: c.AttestationPath,
		// Auth fields are passed through directly.
		BasicAuthUsername: c.BasicAuthUsername,
		BasicAuthPassword: c.BasicAuthPassword,
		BearerToken:       c.BearerToken,
	}

	if c.AuthorizedSigners != "" {
		parts := strings.Split(c.AuthorizedSigners, ",")
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				parsed.AuthorizedSigners = append(parsed.AuthorizedSigners, s)
			}
		}
	}
	return parsed, nil
}

// AttestationInfo holds the result of parsing and verifying an attestation bundle
type AttestationInfo struct {
	Path             string `json:"path"`
	Exists           bool   `json:"exists"`
	Verified         bool   `json:"verified"`
	SignerIdentity   string `json:"signer_identity"`
	SignerIssuer     string `json:"signer_issuer"`
	SubjectDigestAlg string `json:"subject_digest_alg,omitempty"`
	SubjectDigest    string `json:"subject_digest,omitempty"`
	Timestamp        string `json:"timestamp"`
	Error            string `json:"error,omitempty"`
}

var allowedSchemes = map[string]struct{}{
	"http":  {},
	"https": {},
	"git":   {},
	"oci":   {},
	"file":  {},
}

func (c *PluginConfig) Validate() error {
	if c.FilePath == "" {
		return errors.New("file path is required")
	}

	// Validate file path scheme: must be either a relative path (no scheme)
	// or a URI using one of the allowed schemes.
	u, _ := url.Parse(c.FilePath)
	if u.Scheme != "" {
		if _, ok := allowedSchemes[u.Scheme]; !ok {
			return fmt.Errorf("unsupported file path scheme: %s", u.Scheme)
		}
	}

	if c.AttestationPath != "" {
		u, _ := url.Parse(c.AttestationPath)
		if u.Scheme != "" {
			if _, ok := allowedSchemes[u.Scheme]; !ok {
				return fmt.Errorf("unsupported attestation path scheme: %s", u.Scheme)
			}
		}
	}

	return nil
}

// TrackedFileInfo holds information about a tracked file and its attestation
type TrackedFileInfo struct {
	Path              string           `json:"path"`
	Content           []byte           `json:"content"`
	Exists            bool             `json:"exists"`
	SHA               string           `json:"sha,omitempty"`    // SHA-256
	SHA512            string           `json:"sha512,omitempty"` // SHA-512
	Attestation       *AttestationInfo `json:"attestation"`
	AuthorizedSigners []string         `json:"authorized_signers"`
}

type FileAttestationPlugin struct {
	Logger hclog.Logger

	config       *PluginConfig
	parsedConfig *ParsedConfig
}

func (l *FileAttestationPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.Logger.Info("Configuring File Attestation Plugin")
	config := &PluginConfig{}

	if err := mapstructure.Decode(req.Config, config); err != nil {
		l.Logger.Error("Error decoding config", "error", err)
		return nil, err
	}

	if err := config.Validate(); err != nil {
		l.Logger.Error("Error validating config", "error", err)
		return nil, err
	}

	l.config = config
	// Parse JSON-encoded configuration fields
	parsed, err := config.Parse()
	if err != nil {
		l.Logger.Error("Error parsing config", "error", err)
		return nil, err
	}
	l.parsedConfig = parsed

	return &proto.ConfigureResponse{}, nil
}

func (l *FileAttestationPlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()

	trackedFile, err := l.GatherTrackedFileAttestations(ctx)
	if err != nil {
		l.Logger.Warn("Error gathering tracked file attestations", "error", err)
	}

	evidences, err := l.EvaluatePolicies(ctx, trackedFile, req)
	if err != nil {
		l.Logger.Error("Error evaluating policies", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}
	l.Logger.Debug("calculated evidences", "evidences", evidences)
	if err := apiHelper.CreateEvidence(ctx, evidences); err != nil {
		l.Logger.Error("Error creating evidence", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	return &proto.EvalResponse{
		Status: proto.ExecutionStatus_SUCCESS,
	}, nil
}

// FetchFileContent retrieves the content of a file from the repository.
// Returns the file content, whether the file exists, and any error.
func (l *FileAttestationPlugin) FetchFileContent(ctx context.Context, path string) ([]byte, bool, error) {
	if path == "" {
		return nil, false, nil
	}

	u, err := url.Parse(path)
	if err != nil {
		return nil, false, fmt.Errorf("invalid path: %w", err)
	}

	switch u.Scheme {
	case "", "file":
		// Local filesystem path. For file:// URIs, use the URL path component.
		fsPath := path
		if u.Scheme == "file" {
			fsPath = u.Path
		}
		data, err := os.ReadFile(fsPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("failed to read file: %w", err)
		}
		return data, true, nil

	case "http", "https", "oci":
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, false, fmt.Errorf("failed to create request: %w", err)
		}

		// Apply authentication headers if configured.
		if l.config.BasicAuthUsername != "" || l.config.BasicAuthPassword != "" {
			req.SetBasicAuth(l.config.BasicAuthUsername, l.config.BasicAuthPassword)
		}
		if l.config.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+l.config.BearerToken)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, false, fmt.Errorf("failed to fetch %s: %w", path, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return nil, false, nil
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, false, fmt.Errorf("unexpected status code %d for %s", resp.StatusCode, path)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, false, fmt.Errorf("failed to read response body: %w", err)
		}
		return body, true, nil

	case "git":
		// Recognized but not yet implemented fetch mechanism.
		return nil, false, fmt.Errorf("git scheme is not supported for direct content fetching")

	default:
		return nil, false, fmt.Errorf("unsupported URI scheme: %s", u.Scheme)
	}
}

// ParseAttestationBundle parses a Sigstore attestation bundle and extracts signer information.
// Supports both Sigstore bundle format and simple DSSE envelope format.
func (l *FileAttestationPlugin) ParseAttestationBundle(content []byte) (*AttestationInfo, error) {
	info := &AttestationInfo{
		Exists: true,
	}

	// Try to parse as Sigstore bundle format first
	var bundle struct {
		MediaType            string `json:"mediaType"`
		VerificationMaterial struct {
			Certificate struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificate"`
			TlogEntries []struct {
				IntegratedTime string `json:"integratedTime"`
				LogID          struct {
					KeyID string `json:"keyId"`
				} `json:"logId"`
				CanonicalizedBody string `json:"canonicalizedBody"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
		DsseEnvelope struct {
			Payload     string `json:"payload"`
			PayloadType string `json:"payloadType"`
			Signatures  []struct {
				Sig   string `json:"sig"`
				KeyID string `json:"keyid"`
			} `json:"signatures"`
		} `json:"dsseEnvelope"`
	}

	if err := json.Unmarshal(content, &bundle); err != nil {
		info.Error = fmt.Sprintf("failed to parse attestation bundle: %v", err)
		return info, nil
	}

	// Check if this looks like a valid bundle
	if bundle.MediaType != "" || len(bundle.VerificationMaterial.TlogEntries) > 0 {
		info.Verified = true // Bundle exists and is parseable

		// Extract timestamp from tlog entry if available
		if len(bundle.VerificationMaterial.TlogEntries) > 0 {
			info.Timestamp = bundle.VerificationMaterial.TlogEntries[0].IntegratedTime
		}

		// Try to extract signer identity from certificate
		if bundle.VerificationMaterial.Certificate.RawBytes != "" {
			// Certificate is base64-encoded DER
			certBytes, err := base64.StdEncoding.DecodeString(bundle.VerificationMaterial.Certificate.RawBytes)
			if err == nil {
				// Parse certificate to extract subject/SAN
				signerInfo := l.extractSignerFromCertificate(certBytes)
				info.SignerIdentity = signerInfo.Identity
				info.SignerIssuer = signerInfo.Issuer
			}
		}

		// Try to extract subject digest (algorithm + value) from the DSSE payload.
		if bundle.DsseEnvelope.Payload != "" {
			if err := l.populateSubjectDigestFromPayload(info, bundle.DsseEnvelope.Payload); err != nil {
				// Non-fatal: record error but still return parsed attestation info.
				if info.Error == "" {
					info.Error = fmt.Sprintf("failed to parse subject digest: %v", err)
				}
			}
		}

		return info, nil
	}

	// Try parsing as simple DSSE envelope
	var dsse struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}

	if err := json.Unmarshal(content, &dsse); err == nil && dsse.PayloadType != "" {
		info.Verified = len(dsse.Signatures) > 0
		if len(dsse.Signatures) > 0 {
			info.SignerIdentity = dsse.Signatures[0].KeyID
		}
		// Extract subject digest from payload if present.
		if dsse.Payload != "" {
			if err := l.populateSubjectDigestFromPayload(info, dsse.Payload); err != nil {
				if info.Error == "" {
					info.Error = fmt.Sprintf("failed to parse subject digest: %v", err)
				}
			}
		}
		return info, nil
	}

	info.Error = "unrecognized attestation format"
	return info, nil
}

// signerInfo holds extracted signer information from a certificate
type signerInfo struct {
	Identity string
	Issuer   string
}

// Fulcio OIDC extension OIDs for Sigstore certificates
// See: https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
var (
	// OID 1.3.6.1.4.1.57264.1.1 - Issuer (OIDC provider URL)
	oidFulcioIssuer = []int{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	// OID 1.3.6.1.4.1.57264.1.8 - Issuer (v2)
	oidFulcioIssuerV2 = []int{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// extractSignerFromCertificate extracts signer identity from an X.509 certificate.
// For Sigstore/Fulcio certificates, this extracts the OIDC identity from SANs
// and the issuer from Fulcio-specific extensions.
func (l *FileAttestationPlugin) extractSignerFromCertificate(certDER []byte) signerInfo {
	info := signerInfo{}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		l.Logger.Debug("Failed to parse X.509 certificate", "error", err)
		return info
	}

	// Extract identity from Subject Alternative Names (SANs)
	// Fulcio certificates store the OIDC identity in SANs
	if len(cert.EmailAddresses) > 0 {
		// Email-based identity (e.g., user@example.com)
		info.Identity = cert.EmailAddresses[0]
	} else if len(cert.URIs) > 0 {
		// URI-based identity (e.g., GitHub Actions OIDC)
		// Format: https://github.com/owner/repo/.github/workflows/workflow.yml@refs/heads/main
		info.Identity = cert.URIs[0].String()
	} else if len(cert.DNSNames) > 0 {
		// DNS-based identity (less common for Sigstore)
		info.Identity = cert.DNSNames[0]
	}

	// Extract issuer from Fulcio-specific extensions
	for _, ext := range cert.Extensions {
		if oidEqual(ext.Id, oidFulcioIssuer) || oidEqual(ext.Id, oidFulcioIssuerV2) {
			// The extension value is typically a UTF8String or IA5String
			// For simplicity, we treat it as a string directly
			info.Issuer = cleanExtensionValue(ext.Value)
			break
		}
	}

	// Fallback: use certificate issuer CN if no Fulcio extension found
	if info.Issuer == "" && len(cert.Issuer.CommonName) > 0 {
		info.Issuer = cert.Issuer.CommonName
	}

	return info
}

// oidEqual compares two OID slices for equality
func oidEqual(a []int, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// cleanExtensionValue removes ASN.1 encoding artifacts from extension values
func cleanExtensionValue(value []byte) string {
	// ASN.1 UTF8String or IA5String typically has a 2-byte header (tag + length)
	// We try to extract the actual string content
	if len(value) > 2 {
		// Check for common ASN.1 string type tags
		tag := value[0]
		if tag == 0x0C || tag == 0x16 || tag == 0x13 { // UTF8String, IA5String, PrintableString
			length := int(value[1])
			if length <= len(value)-2 {
				return string(value[2 : 2+length])
			}
		}
	}
	// Fallback: try to extract printable content
	result := strings.TrimFunc(string(value), func(r rune) bool {
		return r < 32 || r > 126
	})
	// Try to parse as URL to validate
	if _, err := url.Parse(result); err == nil {
		return result
	}
	return string(value)
}

// populateSubjectDigestFromPayload decodes a base64-encoded DSSE payload and
// attempts to extract the first subject digest (algorithm + value) from an
// in-toto style statement.
func (l *FileAttestationPlugin) populateSubjectDigestFromPayload(info *AttestationInfo, b64Payload string) error {
	payloadBytes, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	var stmt struct {
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
		return fmt.Errorf("unmarshal statement: %w", err)
	}
	// TODO - search based on subject name instead
	// this is to cover a single attestation for a whole collection.
	if len(stmt.Subject) == 0 || len(stmt.Subject[0].Digest) == 0 {
		return nil
	}
	// Prefer sha256 if available; otherwise fall back to first available algorithm.
	validShas := []string{"sha256", "sha512"}
	for _, validSha := range validShas {
		if val, ok := stmt.Subject[0].Digest[validSha]; ok {
			info.SubjectDigestAlg = validSha
			info.SubjectDigest = val
			return nil
		}
	}
	// if empty, get the first one.
	// This will break later on depending on policy support
	// But at least users will figure out why
	for alg, val := range stmt.Subject[0].Digest {
		info.SubjectDigestAlg = alg
		info.SubjectDigest = val
		break
	}
	l.Logger.Warn("No supported digest algorithm found in attestation; using first available", "algorithm", info.SubjectDigestAlg, "digest", info.SubjectDigest)
	return nil
}

// GatherTrackedFileAttestations fetches attestations for all configured tracked files.
func (l *FileAttestationPlugin) GatherTrackedFileAttestations(ctx context.Context) (*TrackedFileInfo, error) {
	if l.parsedConfig == nil {
		return nil, nil
	}

	fileInfo := &TrackedFileInfo{
		Path:              l.config.FilePath,
		Content:           nil,
		Exists:            false,
		Attestation:       nil,
		AuthorizedSigners: l.parsedConfig.AuthorizedSigners,
	}

	// Check if the file itself exists
	fileContent, exists, err := l.FetchFileContent(ctx, l.config.FilePath)
	if err != nil || !exists {
		if err != nil {
			l.Logger.Warn("Error checking file existence", "path", l.config.FilePath, "error", err)
		}
		fileInfo.Exists = false
		// Not an error - It is evidence the file isn't valid
		return fileInfo, nil
	}
	fileInfo.Exists = exists
	fileInfo.Content = fileContent
	// Compute SHA256 digest of the file content for policy evaluation.
	sum := sha256.Sum256(fileContent)
	fileInfo.SHA = hex.EncodeToString(sum[:])
	// Compute SHA512 digest as well to support policies that compare against
	// attestation subject digests using different algorithms.
	sum512 := sha512.Sum512(fileContent)
	fileInfo.SHA512 = hex.EncodeToString(sum512[:])
	// Fetch the attestation file
	attContent, attExists, err := l.FetchFileContent(ctx, l.config.AttestationPath)
	defaultAttestation := &AttestationInfo{}
	defaultAttestation.Path = l.config.AttestationPath
	if err != nil || !attExists {
		defaultAttestation.Exists = false
		if err != nil {
			l.Logger.Warn("Error fetching attestation file", "path", l.config.AttestationPath, "error", err)
			defaultAttestation.Error = err.Error()
		}
		fileInfo.Attestation = defaultAttestation
		return fileInfo, nil
	}

	attestation, err := l.ParseAttestationBundle(attContent)
	if err != nil {
		l.Logger.Warn("Error parsing attestation bundle", "error", err)
		defaultAttestation.Error = err.Error()
		fileInfo.Attestation = defaultAttestation
		return fileInfo, nil
	}
	attestation.Path = l.config.AttestationPath
	fileInfo.Attestation = attestation

	return fileInfo, nil
}

func (l *FileAttestationPlugin) EvaluatePolicies(ctx context.Context, data *TrackedFileInfo, req *proto.EvalRequest) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	evidences := make([]*proto.Evidence, 0)
	activities = append(activities, &proto.Activity{
		Title: "Collect File Data and attestation data",
		Steps: []*proto.Step{
			{
				Title:       "Authenticate with External System",
				Description: "Authenticate with the external system to access file and attestation data.",
			},
			{
				Title:       "Fetch File and Attestation Data",
				Description: "Retrieve the file content and its associated attestation from the external system.",
			},
			{
				Title:       "Validate File and Attestation",
				Description: "Verify the integrity and authenticity of the fetched file and attestation.",
			},
		},
	})

	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework"),
				},
			},
			Props: nil,
		},
		{
			Title: "Continuous Compliance Framework - File Attestation Repository Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-file-attestation",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework File Attestation Plugin"),
				},
			},
			Props: nil,
		},
	}

	components := []*proto.Component{
		{
			Identifier:  "common-components/file-host",
			Type:        "service",
			Title:       "File Host",
			Description: "The service that hosts and serves the file content. This is the source of truth for the file, providing secure access and integrity verification.",
			Purpose:     "To serve as the authoritative and version-controlled location for a specific software project, enabling secure collaboration, code review, automation, and traceability of changes throughout the development lifecycle.",
			Links: []*proto.Link{
				{
					Href: data.Path,
					Rel:  policyManager.Pointer("component"),
					Text: policyManager.Pointer("File Host Component"),
				},
			},
		},
	}
	if data.Attestation != nil {
		attestationComponent := &proto.Component{
			Identifier:  "common-components/attestation-host",
			Type:        "service",
			Title:       "Attestation Host",
			Description: "The service that hosts and serves the attestation data. This is the source of truth for the attestation, providing secure access and integrity verification.",
			Purpose:     "To serve as the authoritative and version-controlled location for attestation data, enabling secure collaboration, code review, automation, and traceability of changes throughout the development lifecycle.",
			Links: []*proto.Link{
				{
					Href: data.Attestation.Path,
					Rel:  policyManager.Pointer("component"),
					Text: policyManager.Pointer("Attestation Host Component"),
				},
			},
		}
		components = append(components, attestationComponent)
	}
	inventoryLinks := []*proto.Link{
		{
			Href: data.Path,
			Text: policyManager.Pointer("File Path"),
		},
	}
	if data.Attestation != nil {
		inventoryLinks = append(inventoryLinks, &proto.Link{
			Href: data.Attestation.Path,
			Text: policyManager.Pointer("Attestation File Path"),
		})
	}
	inventoryImplementationComponents := []*proto.InventoryItemImplementedComponent{
		{
			Identifier: "common-components/file-host",
		},
	}
	if data.Attestation != nil {
		inventoryImplementationComponents = append(inventoryImplementationComponents, &proto.InventoryItemImplementedComponent{
			Identifier: "common-components/attestation-host",
		})
	}
	inventory := []*proto.InventoryItem{
		{
			Identifier:            fmt.Sprintf("file-collection/%s", data.Path),
			Type:                  "file-collection",
			Title:                 "Collection of files used for evidence",
			Props:                 []*proto.Property{},
			Links:                 inventoryLinks,
			ImplementedComponents: inventoryImplementationComponents,
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/file-host",
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/attestation-host",
		},
	}

	for _, policyPath := range req.GetPolicyPaths() {
		processor := policyManager.NewPolicyProcessor(
			l.Logger,
			map[string]string{
				"provider": "file",
				"type":     "attestation",
				"file":     data.Path,
			},
			subjects,
			components,
			inventory,
			actors,
			activities,
		)
		evidence, err := processor.GenerateResults(ctx, policyPath, data)
		evidences = slices.Concat(evidences, evidence)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	return evidences, accumulatedErrors
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Trace,
		JSONFormat: true,
	})

	fileAtt := &FileAttestationPlugin{
		Logger: logger,
	}

	logger.Info("Starting File Attestation Plugin")
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: fileAtt,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
