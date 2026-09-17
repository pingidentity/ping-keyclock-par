# Keycloak External OIDC PAR Redirect Runbook

## Overview

A native Keycloak provider that uses OIDC PAR and signed OIDC request objects to redirect users through PingOne, PingFederate, or other compatible OIDC services. It provides two authenticator modes: use the non-linking authenticator for registration, Universal Services, IDV, or MFA steps that should return to the current Keycloak flow; use the account-linking authenticator only when the external identity should be intentionally linked or brokered into Keycloak.

## Implementation and Build Requirements

The source bundle implements a native Keycloak OIDC Identity Provider SPI for Java `17`. It supports PAR-based redirects for use with registration, browser-login, PingOne Universal Services, MFA, and other compatible authentication flows.

Build it in an environment with Java `17`, Maven `3.9+`, and the Keycloak dependencies.

### Match `pom.xml` to your Keycloak version

Before building, set the `keycloak.version` property in `pom.xml` to the exact Keycloak server version that will load the provider. Keep all three Keycloak dependencies on that same version:

```xml
<keycloak.version>26.6.2</keycloak.version>
```

The current POM uses these versioned dependencies:

```xml
<dependency>
  <groupId>org.keycloak</groupId>
  <artifactId>keycloak-server-spi</artifactId>
  <version>${keycloak.version}</version>
  <scope>provided</scope>
</dependency>
<dependency>
  <groupId>org.keycloak</groupId>
  <artifactId>keycloak-server-spi-private</artifactId>
  <version>${keycloak.version}</version>
  <scope>provided</scope>
</dependency>
<dependency>
  <groupId>org.keycloak</groupId>
  <artifactId>keycloak-services</artifactId>
  <version>${keycloak.version}</version>
  <scope>provided</scope>
</dependency>
```

Do not update only one Keycloak dependency. The SPI, private SPI, and services artifacts must match the runtime version to avoid compile-time or runtime API mismatches. Also verify the Java compiler level is supported by your Keycloak deployment; this project currently targets Java `17` through the Maven compiler plugin `<release>17</release>` setting and the matching source/target properties.

After changing the version, build from a clean workspace:

```bash
mvn clean package
```

Install the resulting JAR only in a Keycloak server running the same Keycloak version used for compilation. If your deployment uses a different version, update `keycloak.version`, rebuild, and test that version before installing it.

## Architecture

The bundle contains:

* `ExternalOidcParIdentityProvider`, a native OIDC provider with PAR support.
* `ExternalOidcParIdentityProviderFactory`, provider ID `external-oidc-par`.
* `ExternalIdpParRedirectAuthenticatorFactory`, non-linking execution ID `external-idp-par-redirect`.
* `ExternalIdpParAccountLinkingAuthenticatorFactory`, account-linking execution ID `external-idp-par-redirect-link`.
* Signed request-object generation, PAR submission, `login_hint`, nonce validation, and optional PKCE.
* Keycloak service registration files for the Identity Provider and all authenticator factories.

The two authenticator choices are deliberately separate:

| Display name | Execution ID | behaviour |
|---|---|---|
| **External IdP PAR Redirect** | `external-idp-par-redirect` | Redirects to the external OIDC PAR provider, validates the returned OIDC result, and resumes the current authentication flow without creating or linking a federated identity. |
| **External IdP PAR Redirect (Account Linking)** | `external-idp-par-redirect-link` | Uses the native broker callback for intentional first-broker-login and account linking. |

Use `external-idp-par-redirect-link` when account linking is intentional.

### Runtime sequences

The two authenticator modes use different handoff paths.

#### Non-linking Universal Services, registration, IDV, or MFA flow:

`Authentication flow execution → External IdP PAR Redirect → signed request object and PAR submission → external OIDC provider → /broker/{alias}/endpoint?code=...&state=... → token exchange and OIDC validation → redirect to the last Keycloak flow execution → authenticator records success or failure → current authentication flow resumes`

The non-linking callback validates the returned OIDC result, including the authorization code and nonce, without calling Keycloak’s native broker `authenticated()` path. It does not enter first-broker-login or persist a federated identity. Instead, it records the result in the authentication session and redirects back to the current flow.

#### Intentional account-linking flow:

`Authentication flow execution → External IdP PAR Redirect (Account Linking) → /broker/{alias}/login → provider creates signed request object and submits PAR → external OIDC provider → /broker/{alias}/endpoint?code=...&state=... → native broker callback → first-broker-login/account-linking behaviour`

The account-linking path uses Keycloak’s native broker callback and therefore allows normal first-broker-login and account-linking behavior. Use it only when the external identity is intentionally being linked or brokered into Keycloak.

## Build and install

The installation examples below assume Keycloak is running in Docker, the container is named `keycloak`, and Keycloak is installed at `/opt/keycloak` inside the container. Replace the container name, installation path, provider path, and restart command as needed for your environment. If Keycloak is not running in Docker, use the non-Docker instructions below instead of the Docker commands.

```bash
unzip keycloak-external-idp-par.zip
cd keycloak-external-idp-par
mvn clean package
```

The expected provider JAR is:

```text
target/keycloak-external-idp-par-1.0.0.jar
```

### Docker installation

Install the JAR in the Keycloak providers directory and rebuild the optimized server:

```bash
docker exec keycloak rm -f /opt/keycloak/providers/keycloak-external-idp-par-1.0.0.jar
docker cp target/keycloak-external-idp-par-1.0.0.jar keycloak:/opt/keycloak/providers/
docker exec keycloak /opt/keycloak/bin/kc.sh build
docker restart keycloak
```

Replace `keycloak` with the actual container name.

### Non-Docker installation

For a VM, bare-metal, or service installation, copy the provider JAR into the local Keycloak providers directory, rebuild Keycloak, and restart the Keycloak process or service:

```bash
export KEYCLOAK_HOME=/opt/keycloak
rm -f "$KEYCLOAK_HOME/providers/keycloak-external-idp-par-1.0.0.jar"
cp target/keycloak-external-idp-par-1.0.0.jar "$KEYCLOAK_HOME/providers/"
"$KEYCLOAK_HOME/bin/kc.sh" build
sudo systemctl restart keycloak
```

Adjust `KEYCLOAK_HOME` and the service restart command for the local installation. If Keycloak is started manually rather than through systemd, stop and restart that process instead.

## Identity Provider configuration

In the target realm, go to **Identity Providers → Add provider → External OIDC PAR**.

Configure the OIDC fields from the external provider’s discovery document:

| Field | Configuration |
|---|---|
| Alias | A unique alias, such as `pingone-universal-services-oidc` or `pingfederate-mfa-oidc` |
| Issuer | The external OIDC issuer |
| Authorization URL | The external authorization endpoint |
| Token URL | The external token endpoint |
| UserInfo URL | The external UserInfo endpoint, when used |
| JWKS URL | The external JWKS endpoint |
| OAuth client ID | The registered external client ID |
| OAuth client secret | The matching client secret |
| Client authentication | `client_secret_basic` or `client_secret_post` for PAR; the inherited OIDC token client settings apply to the token request |
| Default scopes | The provider’s normal scopes; this implementation also ensures `openid profile email` are requested |
| Validate signatures | Enabled when the external provider exposes usable JWKS metadata |

Configure the custom PAR fields:

| Field | Configuration |
|---|---|
| PAR endpoint | The external provider’s RFC 9126 PAR endpoint |
| Request-object audience | The audience expected by the PAR endpoint, normally the external issuer |
| Request-object signing algorithm | `HS256`, `HS384`, or `HS512`, matching the external client policy |
| PKCE mode | `required-S256` when supported; use `disabled` only when the external client cannot support PKCE |
| `acr_values` | The external policy or MFA value, when required |
| Signed PAR user-attribute allowlist (comma-separated) | Controls only additional raw attributes in `kc_attributes`: blank sends all raw user attributes; populated sends only the listed names. The standard claims `kc_username`, `kc_email`, `kc_given_name`, `kc_family_name`, and `kc_full_name` are always sent separately. |

The HMAC client secret must be at least 32 bytes for HS256, 48 bytes for HS384, or 64 bytes for HS512.

Register this Callback / Redirect URI in the external OIDC provider:

```text
https://<keycloak-host>/realms/<realm>/broker/<provider-alias>/endpoint
```

The callback alias must exactly match the Keycloak Identity Provider alias. The same registered callback is used by both authenticator variants.

## Authentication flow configuration

Copy the relevant built-in flow rather than editing it directly.

### Universal Services, IDV, or MFA flow

Add **External IdP PAR Redirect** and configure **Identity provider alias** with the external PAR provider alias. Use **Required** when the redirect must run for every execution through that flow.

This is the correct choice when PingOne or PingFederate is being used for universal services or assurance step. The successful external OIDC result resumes the existing Keycloak flow; it does not create a Keycloak external identity.

### Account-linking flow

Add **External IdP PAR Redirect (Account Linking)** only where the external identity is intentionally allowed to become a Keycloak broker identity. Configure the provider’s First Login Flow as appropriate for that provider.

This is the correct choice when the external identity is intentionally allowed to become a Keycloak broker identity; otherwise use `External IdP PAR Redirect`.

### Registration flow

Use the non-linking execution after the user has been established when the external provider is only performing IDV or MFA during registration. Use the account-linking execution only when the registration is intentionally creating or linking the external identity through Keycloak’s broker.

### PAR Claims

The signed request object and PAR request include the standard OIDC `login_hint` when a Keycloak username is available. The implementation always sends these five standard Keycloak context claims in the signed request object:

```text
kc_username
kc_email
kc_given_name
kc_family_name
kc_full_name
```

These five claims are always generated and are not controlled by the user-attribute allowlist. If a value is unavailable, the claim is sent with an empty value.

The separate `kc_attributes` object carries additional raw Keycloak user attributes. The provider setting **Signed PAR user-attribute allowlist (comma-separated)** controls only this object and applies to both `external-idp-par-redirect` and `external-idp-par-redirect-link` when they use that provider alias. Enter raw Keycloak user-attribute names, for example `department,employeeNumber,costCenter` - not generated claim names such as `kc_email` or `kc_family_name`.

- **Blank setting:** all raw user attributes are included in `kc_attributes`. The five standard claims above are still sent separately.
- **Populated setting:** only the listed raw user attributes are included in `kc_attributes`; every unlisted raw attribute is excluded. The five standard claims above are still sent unchanged.

Example:

```text
Signed PAR user-attribute allowlist: department,employeeNumber,costCenter
```

This results in a `kc_attributes` object containing only those matching user-attribute keys. Unknown names are ignored. The allowlist limits data included in the signed request object; it does not encrypt the JWT.

### PKCE behaviour

When PKCE is enabled:

* A verifier is generated per authentication attempt.
* The verifier is stored in the active authentication session.
* The S256 challenge is included in the request object and PAR form.
* The verifier is added to the authorization-code token request.
* The flow fails if required PKCE is configured but the verifier is missing.

## Expected response from the external OIDC provider

The external OIDC provider must return a standard OIDC authorization-code result. Do not return a separate custom outcome field to the Keycloak callback.

Successful authorization response to Keycloak:

```text
code=<one-time authorization code>
state=<exact state value received in the authorization request>
```

The `state` value must be returned unchanged. On failure, return an OIDC error response such as `error=access_denied`, with an optional URL-encoded `error_description`, unchanged `state`, and no `code`.


The authorization code must resolve at the configured Token URL to a JSON response containing at least:

```json
{
  "access_token": "<opaque or JWT access token>",
  "token_type": "Bearer",
  "id_token": "<signed OIDC ID token>"
}
```

`expires_in` and `scope` are recommended. A `refresh_token` is not required for this flow.

For MFA or assurance signaling, the external OIDC provider should return `acr` and/or `amr` values that identify the assurance level and authentication method. For example, `acr` can identify the completed MFA policy, while `amr` should identify the method or methods used, such as `otp`, `mfa`, `pwd`, or another applicable method.

## Log inspection

* The current source logs callback failures in this format:

  ```text
  External IdP authentication failure: error=access_denied error_description=User denied the request
  ```

  Missing values are logged as `<none>`. Carriage returns, line feeds, and tabs are replaced with spaces, and each value is truncated to 512 characters plus `...` when necessary.
* The non-linking failure branch then clears the temporary markers and returns Keycloak's generic identity-provider error. It does not log authorization codes, tokens, or `state`.

Use these commands to inspect the Keycloak container logs:

```bash
# Follow new Keycloak log entries
docker logs -f keycloak

# Review recent entries related to this provider and authentication errors
docker logs --since 15m keycloak 2>&1 | grep -Ei 'External IdP authentication failure|External IdP PAR|identity provider|authentication|callback|error|unexpected'

# Show only the callback error fields logged by the provider
docker logs --since 15m keycloak 2>&1 | grep -Ei 'External IdP authentication failure|error_description'
```