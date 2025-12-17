# Compliance Framework - File Attestation Plugin

The **File Attestation Plugin** verifies that a given file exists and that its
attestation is present and valid, then exposes this information as evidence to
the Continuous Compliance Framework.

Typical use cases:

- Ensure a critical artifact (e.g. SBOM, manifest, binary) is present.
- Verify that the artifact is covered by a signed Sigstore-style attestation.
- Enforce that the signer of an attestation is on an approved list.
- Ensure a given standard-based report is compliant (SARIF, CTRF)

This plugin is intended to be run as part of an aggregate agent and will execute
your policy suite for the configured file and its attestation.

---

## Authentication

The plugin can fetch both the file and its attestation from different locations:

- Local filesystem (`/path/to/file` or `file:///path/to/file`)
- HTTP / HTTPS endpoints
- OCI-style endpoints (treated as HTTP(S) by this plugin)

Depending on where the file and attestation live, you may need authentication:

- **Basic Auth**
  - `basic_auth_username`
  - `basic_auth_password`
- **Bearer Token**
  - `bearer_token`

These credentials are automatically applied to `http`, `https`, and `oci` URIs.

> Note: There is no GitHub-specific authentication in this plugin. Any GitHub
> access should be provided via standard HTTP(S) endpoints secured with the
> mechanisms above.

---

## Configuration

This plugin is configured via the agent YAML under `plugins`:

```yaml
plugins:
  file_attestation:
    # Required: path to the file whose existence should be checked.
    # Can be:
    #   - Relative path (treated as local filesystem)
    #   - file:///absolute/path
    #   - http(s)://... or oci://...
    path: "file:///etc/myapp/config.yaml"

    # Optional: path to the attestation associated with the file.
    # Same URI formats as `path`.
    attestation_path: "https://attest.example.com/config.yaml.att.json"

    # Optional: comma-separated list of authorized signers for the attestation.
    # Example: emails, identities, or URIs depending on your trust model.
    authorized_signers: "alice@example.com,bob@example.com"

    # Optional: credentials for HTTP/HTTPS/OCI endpoints.
    basic_auth_username: ""
    basic_auth_password: ""
    bearer_token: ""

```

### Path rules

- `path` is **required**.
- `path` and `attestation_path` may be:
  - Relative filesystem paths (no URI scheme).
  - `file://` URIs (local filesystem).
  - `http://`, `https://`, or `oci://` URIs.
- Any other schemes (including `git://`) are rejected during validation.

The plugin also normalizes plain filesystem paths to `file://` internally so
they can be handled consistently.

---

## Integration testing

The repository includes unit tests and optional integration tests.

If your configuration uses remote endpoints that require authentication, set the
appropriate environment variables or configuration for those tests to run
successfully.

A typical test invocation looks like:

```shell
go test ./... -v
```

If you add integration tests that depend on external services, consider gating
them behind build tags (for example, `-tags integration`) and document any
required environment variables.

---

## Policies

Policies are written in OPA/Rego and must live under the
`compliance_framework` package namespace.

Example:

```rego
# deny_unsigned_file.rego
# package compliance_framework.[YOUR_RULE_PATH]
package compliance_framework.deny_unsigned_file

deny[msg] {
  input.attestation.exists == false
  msg := "critical file is missing an attestation"
}
```

The plugin exposes information about:

- File path and existence
- Attestation presence and verification status
- Attestation signer identity and issuer (where available)
- Configured authorized signers

You can use these fields to write policies such as:

- Deny when the file does not exist.
- Deny when the attestation is missing or invalid.
- Deny when the signer is not one of the `authorized_signers`.

---

## Releases

This plugin is released using GoReleaser to build binaries, and GOOCI to upload artifacts to OCI,
which will ensure a binary is built for most OS and Architecture combinations.

You can find the binaries on each release of this plugin in the GitHub Releases page.

You can find the OCI implementations in the GitHub Packages page.
