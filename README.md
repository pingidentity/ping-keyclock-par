# Keycloak External OIDC PAR Redirect

## Overview

A native Keycloak provider that uses OAuth 2.0 Pushed Authorization Requests (PAR) to redirect users to PingOne, PingFederate, or other compatible OIDC services. It provides two authenticator modes:

- A **non-linking** authenticator for registration, Universal Services, IDV, or MFA steps that should return to the current Keycloak flow.
- An **account-linking** authenticator for when the external identity should be intentionally linked or brokered into Keycloak.

## Implementation and Build Requirements

This project implements a native Keycloak OIDC Identity Provider SPI for Java `17`. It supports PAR-based redirects for use with registration, browser-login, PingOne Universal Services, MFA, and other compatible authentication flows. It has no runtime dependencies beyond Keycloak itself: request objects are signed with Keycloak's own JOSE implementation.

Build it in an environment with Java `17`, Maven `3.9+`, and the Keycloak dependencies.

### Match `pom.xml` to your Keycloak version

The `keycloak.version` property in `pom.xml` sets the Keycloak version the provider is compiled against. Keep all three Keycloak dependencies on that same version:

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

Without a local JDK 17 and Maven, build in a container instead:

```bash
docker run --rm -v "$PWD":/src -v "$HOME/.m2":/root/.m2 -w /src maven:3.9.9-eclipse-temurin-17 mvn -B clean verify
```

A JAR built against one Keycloak release normally works on other patch releases of the same minor version, including the Red Hat build of Keycloak. For example, the JAR built against `26.6.2` was checked against Red Hat build of Keycloak `26.6.6.redhat-00001`, and the Keycloak APIs it uses are identical. For a 26.6.x patch release, test the existing JAR on that version rather than rebuilding. Building against a Red Hat version string also requires Red Hat's Maven repository.

The provider uses Keycloak SPIs that Keycloak marks as internal, so they can change between minor releases. For a different minor or major version (for example 26.7 or 27), set `keycloak.version` to that version, rebuild, and test it before installing.

## Architecture

The project contains:

* `ExternalOidcParIdentityProvider`, a native OIDC provider with PAR support. It extends Keycloak's generic `OIDCIdentityProvider` (not the Keycloak-to-Keycloak provider), so opaque PingFederate access tokens are accepted.
* `ExternalOidcParIdentityProviderFactory`, provider ID `external-oidc-par`.
* `ExternalIdpParRedirectAuthenticatorFactory`, non-linking execution ID `external-idp-par-redirect`.
* `ExternalIdpParAccountLinkingAuthenticatorFactory`, account-linking execution ID `external-idp-par-redirect-link`.
* PAR submission (as a signed request object or as plain parameters), `login_hint`, nonce validation, `acr` enforcement, user binding for the non-linking path, and S256 PKCE.
* Keycloak service registration files for the Identity Provider and all authenticator factories.

The two authenticator choices are deliberately separate:

| Display name | Execution ID | Behavior |
|---|---|---|
| **External IdP PAR Redirect** | `external-idp-par-redirect` | Redirects to the external OIDC PAR provider. It validates the returned OIDC result and checks that the external identity is the Keycloak user. It then resumes the current authentication flow without creating or linking a federated identity. |
| **External IdP PAR Redirect (Account Linking)** | `external-idp-par-redirect-link` | Uses the native broker callback for intentional first-broker-login and account linking. This is a **terminal broker login**: the session completes as the user linked to the external identity, and executions after it do not run. Do not use it as an MFA or step-up check. |

Use `external-idp-par-redirect-link` when account linking is intentional.

### Runtime sequences

The two authenticator modes use different handoff paths.

#### Non-linking Universal Services, registration, IDV, or MFA flow

`Authentication flow execution → External IdP PAR Redirect → PAR submission → external OIDC provider → /broker/{alias}/endpoint?code=...&state=... → token exchange and OIDC validation (signature, issuer, audience, nonce, acr, user binding) → redirect to the last Keycloak flow execution → authenticator records success or failure → current authentication flow resumes`

The non-linking callback validates the returned OIDC result without calling Keycloak's native broker `authenticated()` path. It does not enter first-broker-login or persist a federated identity. Instead, it records the result in the authentication session and redirects back to the current flow. The result is bound to the execution, provider alias, and Keycloak user that started the redirect, so it cannot satisfy a different step, provider, or user.

On failure, the flow shows Keycloak's "Unexpected error when authenticating with identity provider" error page. Failures include an external `error` response, a token or validation failure, or a user-binding or `acr` mismatch. The redirect is not retried in a loop.

#### Intentional account-linking flow

`Authentication flow execution → External IdP PAR Redirect (Account Linking) → /broker/{alias}/login → provider submits PAR → external OIDC provider → /broker/{alias}/endpoint?code=...&state=... → native broker callback → first-broker-login/account-linking behavior`

The account-linking path uses Keycloak's native broker callback unchanged, and therefore allows normal first-broker-login and account-linking behavior. The identity-provider button on the login page uses the same path. Use it only when the external identity is intentionally being linked or brokered into Keycloak.

## Build and install

The installation examples below make these assumptions:

* Keycloak is running in Docker.
* The container is named `keycloak`.
* Keycloak is installed at `/opt/keycloak` inside the container.

Replace the container name, installation path, provider path, and restart command as needed for your environment. If Keycloak is not running in Docker, use the non-Docker instructions below instead of the Docker commands.

```bash
git clone https://github.com/pingidentity/ping-keyclock-par.git
cd ping-keyclock-par
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

### TLS trust

The PAR, token, UserInfo, and JWKS calls all use Keycloak's outbound HTTP client. They therefore honor Keycloak's truststore (`truststore-paths`, or certificates placed in `conf/truststores`) and proxy settings. If PingFederate uses a private CA, add that CA to Keycloak's truststore.

## Identity Provider configuration

In the target realm, go to **Identity Providers → Add provider → External OIDC PAR**.

Configure the OIDC fields from the external provider's discovery document:

| Field | Configuration |
|---|---|
| Alias | A unique alias, such as `pingone-universal-services-oidc` or `pingfederate-mfa-oidc` |
| Issuer | **Required.** The external OIDC issuer. It is the default request-object audience and is checked against the ID token `iss`. |
| Authorization URL | The external authorization endpoint |
| Token URL | The external token endpoint |
| UserInfo URL | The external UserInfo endpoint. Recommended: user binding reads `preferred_username` from UserInfo when the ID token does not carry it. |
| JWKS URL | The external JWKS endpoint |
| Validate signatures | **Required (on).** The provider refuses to run with signature validation off. |
| Disable nonce | **Must be off.** |
| Use PKCE (Keycloak built-in) | **Must be off.** This provider sends PKCE through PAR; use the **PKCE mode** setting below. |
| OAuth client ID | The registered external client ID |
| OAuth client secret | The matching client secret. Vault references (`${vault.key}`) are supported. With the `signed-request-object` format, the secret is also the HMAC key for the request object, so it is required even when client authentication uses `private_key_jwt`. |
| Client authentication | Used for both the PAR request and the token request: `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, or `private_key_jwt`. |
| Default scopes | Blank sends `openid profile email`. When set, exactly these scopes plus `openid` are sent. PingFederate rejects scopes a client is not allowed to request (`invalid_scope`). |

Configure the custom PAR fields:

| Field | Configuration |
|---|---|
| PAR endpoint | The external provider's RFC 9126 PAR endpoint. Must be `https` (loopback hosts are exempt for development). |
| Request-object audience | The audience expected by the PAR endpoint. Defaults to the Issuer. |
| PAR request format | `signed-request-object` (default): the parameters go in a request object signed with the client secret, and the core parameters are repeated outside it. Use this for PingOne. `plain-parameters`: the same parameters are sent directly in the client-authenticated PAR request, with no request object. Use this for PingFederate, which only accepts RSA- or EC-signed request objects. See [PAR Claims](#par-claims). |
| Request-object signing algorithm | `HS256` (default), `HS384`, or `HS512`, matching the external client policy. Ignored for `plain-parameters`. |
| PKCE mode | `required-S256` (default) or `disabled`. Use `disabled` only when the external client cannot support PKCE. |
| `acr_values` | Space-separated `acr` values to request, such as the external MFA policy. A non-linking step can request its own values instead; see [Choosing the MFA method per user](#choosing-the-mfa-method-per-user). |
| Require returned acr to match acr_values | Default on. When `acr_values` is set, ID tokens whose `acr` is not one of the requested values are rejected, on both the non-linking and the account-linking paths. When a step sets its own `acr_values`, the returned `acr` must be one of the step's values. |
| PAR user-attribute allowlist (comma-separated) | Controls which raw user attributes are sent as `kc_attr_<name>` parameters: blank sends **none**, `*` sends all, a list sends only the listed names. The standard `kc_*` claims are always sent. |
| Non-linking user binding | `required` (default) or `disabled`. See [User binding](#user-binding). |
| User binding claims | Default `preferred_username,sub`. Comma-separated ID-token or UserInfo claims; the first one present is compared. |
| User binding attribute | Default `username`. The Keycloak value compared with the claim: `username`, `email` (both case-insensitive), `id`, or a user attribute name (exact match). |

With `signed-request-object`, the HMAC client secret must be at least 32 bytes for HS256, 48 bytes for HS384, or 64 bytes for HS512.

Register this Callback / Redirect URI in the external OIDC provider:

```text
https://<keycloak-host>/realms/<realm>/broker/<provider-alias>/endpoint
```

The callback alias must exactly match the Keycloak Identity Provider alias. Keycloak builds this URL from its configured hostname (`hostname`, or `KC_HOSTNAME` in a container), so register it with exactly that scheme, host, and port. The same registered callback is used by both authenticator variants.

### User binding

The non-linking execution is typically an MFA or assurance step for a user Keycloak has already identified. A successful external login is only accepted if it is **the same person**; otherwise someone who knows a user's password could finish the step by signing in at the external provider as themselves. `login_hint` is only a hint and is not enough.

With **Non-linking user binding** set to `required`, the check is decided as follows:

1. **The Keycloak user already has a federated link for this provider alias.** The ID token `sub` must equal the linked external user ID.
2. **There is no link.** The first configured claim that is present (ID token first, then UserInfo) must equal the configured Keycloak value. If the first present claim does not match, the step fails. It does not fall through to the next claim.
3. **No Keycloak user is established when the step runs.** The step fails. Set binding to `disabled` only for steps that run before a user exists, such as IDV before registration completes. With binding disabled, the step proves only that someone completed the external flow.

Error log lines name the claim and attribute but never their values.

## Provider setup

### PingFederate

| Keycloak field | PingFederate value |
|---|---|
| Issuer | The PingFederate base URL, such as `https://pf.example.com:9031` (or the virtual host issuer the client uses) |
| Authorization URL | `<base>/as/authorization.oauth2` |
| Token URL | `<base>/as/token.oauth2` |
| UserInfo URL | `<base>/idp/userinfo.openid` |
| JWKS URL | `<base>/pf/JWKS` |
| PAR endpoint | `<base>/as/par.oauth2` |

PingFederate OAuth client settings:

* **Grant type:** Authorization Code. Redirect URI is the Keycloak broker endpoint above.
* **PAR request format: set Keycloak's to `plain-parameters`.** PingFederate only accepts request objects signed with the client's RSA or EC keys, so it rejects the HMAC-signed request object. Leave **Require Signed Requests** off on the PingFederate client.
* **Require Pushed Authorization Requests:** on. The client-authenticated PAR request then carries every parameter, and the browser only ever sees `client_id` and `request_uri`.
* **Client authentication:** Client Secret (`client_secret_basic` or `client_secret_post`), or Private Key JWT.
* **PKCE:** enable **Require Proof Key for Code Exchange (PKCE)**.
* **Scopes:** allow `openid profile email`, or set Keycloak's **Default scopes** to exactly what the client may request.
* **Identity for user binding:** make PingFederate return the Keycloak username as `preferred_username`, either in the ID token or through UserInfo, from the OIDC policy attribute contract. Alternatively, if your OIDC policy maps `sub` to the username, set **User binding claims** to `sub`.
* **`acr`:** when `acr_values` is set, use a Requested AuthN Context Authentication Selector (or equivalent policy) so the ID token's `acr` is one of the requested values. Give the selector one result value per method that Keycloak steps request (for example `email` and `sms`), matching exactly and case-sensitively, and leave **Add or Update AuthN Context Attribute** and **Override AuthN Context for Flow** selected so the result becomes the ID token's `acr`. If no selector value matches, PingFederate moves on to its next policy, which may be weaker; the provider then rejects the result because `acr` does not match. Put this policy first.
* **Access token manager:** any. Reference (opaque) and JWT access tokens both work, because the provider does not validate the access token.
* **TLS:** if PingFederate's certificate comes from a private CA, add it to Keycloak's truststore.

PingFederate returns `201 Created` from the PAR endpoint, and the provider redirects immediately with only `client_id` and `request_uri` on the front channel.

**PAR Reference Timeout:** PingFederate checks the `request_uri` again when its authentication policy finishes, so the timeout must cover the whole MFA step. The default of 60 seconds is often too short; a user who takes longer comes back with `error=invalid_request_uri`. Set **PAR Reference Timeout** in the authorization server settings to 300 seconds (FAPI 2.0 requires less than 600).

### PingOne

| Keycloak field | PingOne value (use your region's domain) |
|---|---|
| Issuer | `https://auth.pingone.com/<envId>/as` |
| Authorization URL | `https://auth.pingone.com/<envId>/as/authorize` |
| Token URL | `https://auth.pingone.com/<envId>/as/token` |
| UserInfo URL | `https://auth.pingone.com/<envId>/as/userinfo` |
| JWKS URL | `https://auth.pingone.com/<envId>/as/jwks` |
| PAR endpoint | `https://auth.pingone.com/<envId>/as/par` |

PingOne's `sub` is the PingOne user ID, and `preferred_username` (from the `profile` scope via UserInfo) is the PingOne username. The default binding (`preferred_username,sub` against the Keycloak `username`) therefore works when PingOne usernames match Keycloak usernames. If they differ, store the PingOne user ID in a Keycloak attribute and bind `sub` to that attribute.

## Authentication flow configuration

Copy the relevant built-in flow rather than editing it directly.

### Universal Services, IDV, or MFA flow

Add **External IdP PAR Redirect** after the step that identifies the user, and configure **Identity provider alias** with the external PAR provider alias. Use **Required** when the redirect must run for every execution through that flow.

In a copy of the browser flow, put the step inside the forms subflow, after **Username Password Form**. Do not add it at the top level next to **Cookie** and **Identity Provider Redirector**: Keycloak ignores alternatives that sit at the same level as a required step (it logs `REQUIRED and ALTERNATIVE elements at same level`), so cookie SSO would stop working.

Use this when PingOne or PingFederate provides Universal Services or an assurance step. A successful external OIDC result for the same user resumes the existing Keycloak flow. It does not create a Keycloak external identity.

The step's settings:

| Setting | Configuration |
|---|---|
| Identity provider alias | **Required.** The External OIDC PAR provider alias. |
| acr_values for this step | Optional. Space-separated `acr` values this step requests instead of the provider's `acr_values`. Blank uses the provider's. |

#### Choosing the MFA method per user

To let the Keycloak flow choose the external MFA method, add one **External IdP PAR Redirect** step per method, each with its own **acr_values for this step**, and put each step in a conditional subflow. For example, use SMS when the user has an `sms` attribute and email otherwise:

```text
SMS MFA (Conditional)
├─ Condition - user attribute: sms, .+, regex on                        Required
└─ External IdP PAR Redirect: acr_values for this step = sms            Required
Email MFA (Conditional)
├─ Condition - user attribute: sms, .+, regex on, Negate output on      Required
└─ External IdP PAR Redirect: acr_values for this step = email          Required
```

In each condition, **Attribute name** is `sms` and **Expected attribute value** is `.+`.

* Make the two conditions exact opposites, so that every user runs exactly one MFA step.
* Both steps use the same provider alias, external client, redirect URI, and secret.
* With **Require returned acr to match acr_values** on, a step accepts only its own value: if the SMS step's ID token comes back with `acr` `email`, the step fails.
* If the attribute that picks the method also holds the phone number, let only administrators edit it in the user profile. It decides where codes are sent.

On the PingFederate side, a Requested AuthN Context Authentication Selector with the result values `email` and `sms` branches the policy to the matching adapter. See [PingFederate](#pingfederate).

### Account-linking flow

Add **External IdP PAR Redirect (Account Linking)** only where the external identity is intentionally allowed to become a Keycloak broker identity. Configure the provider's First Login Flow as appropriate for that provider. This execution ends the flow with a broker login. Executions after it do not run, and the session belongs to the user linked to the external identity.

Otherwise use `External IdP PAR Redirect`.

If no flow uses the account-linking step, close the broker login path for this provider. Turn on **Hide on login page**, and set **First login flow override** to a flow that contains only **Deny access**. Otherwise anyone can open `/broker/{alias}/login` (or use `kc_idp_hint`) to sign in through the external provider and create or link a Keycloak account. The non-linking step never enters the first login flow, so it is unaffected.

### Registration flow

Use the non-linking execution after the user has been established when the external provider is only performing IDV or MFA during registration. If it must run before a user exists, set **Non-linking user binding** to `disabled` on that provider. Use the account-linking execution only when the registration is intentionally creating or linking the external identity through Keycloak's broker.

### PAR Claims

The **PAR request format** setting decides how the request is sent:

- **`signed-request-object` (default):** every parameter below is a claim in a request object signed with the client secret. `response_type`, `redirect_uri`, `scope`, `state`, `login_hint`, `acr_values` and the PKCE challenge are repeated as PAR form parameters outside it, and the authorization server uses the signed values.
- **`plain-parameters`:** the same values are sent as PAR form parameters and there is no request object. The PAR request is client-authenticated over TLS, which protects these values the same way an HMAC signature with the same client secret would.

The request always includes `nonce`, and includes the standard OIDC `login_hint` when a Keycloak username is available. The implementation always sends these five standard Keycloak context claims:

```text
kc_username
kc_email
kc_given_name
kc_family_name
kc_full_name
```

These five claims are always generated and are not controlled by the user-attribute allowlist. If a value is unavailable, the claim is sent with an empty value.

Additional raw Keycloak user attributes are sent as one parameter per allowlisted attribute, named `kc_attr_<name>`. For example, an attribute `sms` is sent as `kc_attr_sms=+15550100`, so an IdP such as PingFederate can track and map it directly.

- **First value only:** an attribute with several values (User Profile **Multivalued** on) sends only its first value.
- **Empty attributes are skipped:** an attribute with no value gets no parameter.
- **No collisions:** the `kc_attr_` prefix keeps attribute names such as `email` from colliding with the fixed `kc_*` claims.

The provider setting **PAR user-attribute allowlist (comma-separated)** controls these parameters, and applies to both `external-idp-par-redirect` and `external-idp-par-redirect-link` when they use that provider alias. Enter raw Keycloak user-attribute names, for example `department,employeeNumber,costCenter`. Do not enter generated claim names such as `kc_email` or `kc_family_name`.

- **Blank setting (default):** no `kc_attr_*` parameters are sent.
- **`*`:** all raw user attributes are sent. This can include data from user federation (for example LDAP DNs) and admin-only attributes; prefer an explicit list.
- **List:** only the listed raw user attributes are included. Unknown names are ignored.

Example:

```text
PAR user-attribute allowlist: department,employeeNumber,costCenter
```

In both formats the request travels only over the back channel (the PAR request), and the browser sees only `client_id` and `request_uri`. The request object is signed, not encrypted.

A request object also carries `iss` (client ID), `aud`, `iat`, `nbf`, `exp` (5 minutes), and a unique `jti`.

### PKCE behavior

PKCE is on by default (`required-S256`). When enabled:

* A verifier is generated per authentication attempt.
* The verifier is stored in the active authentication session and removed after the callback.
* The S256 challenge is sent in the PAR form, and in the request object when one is used.
* The verifier is added to the authorization-code token request.
* The flow fails if the verifier is missing.

Values other than `required-S256` and `disabled` cause a configuration error. `optional` and `required_s256` are also accepted and mean PKCE on.

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

The ID token must meet these requirements:

* It is signed with a key from the JWKS URL.
* `iss` equals the configured Issuer.
* `aud` includes the client ID.
* `nonce` matches the request.
* When `acr_values` is configured, `acr` is one of the requested values (the step's own values when it sets them).
* For the non-linking path, the binding claim must be present in the ID token or UserInfo.

`amr` is not checked but is recommended for audit, with values such as `otp`, `mfa`, or `pwd`.

## Log inspection

The provider logs these lines:

```text
WARN  External IdP authentication failure: error=access_denied error_description=User denied the request
ERROR External IdP PAR non-linking callback validation failed: IdentityBrokerException: External IdP user binding failed: claim 'preferred_username' does not match Keycloak user 'username'
ERROR External IdP PAR non-linking callback validation failed: IdentityBrokerException: External IdP returned acr <value> which is not one of the requested acr_values [<values>]
ERROR Failed to create external IdP PAR request: External IdP PAR returned HTTP 400 error=invalid_request_object error_description=<description>
ERROR External IdP PAR non-linking handoff failed: Validate signatures must be enabled for External OIDC PAR
```

Missing values are logged as `<none>`. Control characters (including CR, LF, tab, and ESC), Unicode format characters, and line or paragraph separators are replaced with spaces. Each value is truncated to 512 characters plus `...` when necessary. The provider never logs authorization codes, tokens, `state`, `request_uri`, secrets, or user-binding claim values.

Use these commands to inspect the Keycloak container logs:

```bash
# Follow new Keycloak log entries
docker logs -f keycloak

# Review recent entries related to this provider and authentication errors
docker logs --since 15m keycloak 2>&1 | grep -Ei 'External IdP|identity provider|authentication|callback|error|unexpected'

# Show only the callback error fields logged by the provider
docker logs --since 15m keycloak 2>&1 | grep -Ei 'External IdP authentication failure|error_description'
```

## Testing

Unit tests cover:

* request-object claims and HMAC signatures
* plain PAR parameters
* the attribute allowlist
* PKCE
* `request_uri` parsing
* log sanitizing
* `acr` enforcement, including per-step `acr_values`
* user binding

They run with `mvn verify`.

Validate against a real PingFederate or PingOne test environment before production.
