package com.pingidentity.keycloak.externalidppar;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.ClientModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.util.AuthenticationFlowURLHelper;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.vault.VaultStringSecret;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Map;

public class ExternalOidcParIdentityProvider extends OIDCIdentityProvider {
    // OIDCIdentityProvider keeps this client-note key private; the inherited
    // preprocessFederatedIdentity() reads the same key for nonce validation.
    private static final String BROKER_NONCE = "BROKER_NONCE";

    public ExternalOidcParIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        AuthenticationSessionModel authSession = request.getAuthenticationSession();
        // A native broker login must never be completed through the non-linking branch.
        ExternalIdpParSupport.clearNonLinkingNotes(authSession);
        try {
            return performParLogin(
                authSession, request.getState().getEncoded(), request.getRedirectUri(),
                authSession == null ? null : authSession.getAuthenticatedUser(),
                value(ExternalIdpParConfig.ACR_VALUES, null)
            );
        } catch (IOException | RuntimeException e) {
            logger.errorf("Failed to create external IdP PAR request: %s",
                ExternalIdpParSupport.safeLogValue(e.getMessage()));
            throw new IdentityBrokerException("Could not create external IdP PAR request", e);
        }
    }

    public Response performNonLinkingLogin(AuthenticationSessionModel authSession,
                                            IdentityBrokerState state,
                                            String redirectUri,
                                            UserModel user,
                                            String stepAcrValues) throws IOException {
        String acrValues = ExternalIdpParSupport.effectiveAcrValues(
            stepAcrValues, value(ExternalIdpParConfig.ACR_VALUES, null));
        Response response = performParLogin(authSession, state.getEncoded(), redirectUri, user, acrValues);
        // The callback checks the returned acr against exactly what this request asked for.
        authSession.setAuthNote(ExternalIdpParConfig.NON_LINKING_ACR_NOTE, acrValues == null ? "" : acrValues);
        return response;
    }

    private Response performParLogin(AuthenticationSessionModel authSession,
                                     String state,
                                     String redirectUri,
                                     UserModel user,
                                     String acrValues) throws IOException {
        if (authSession == null || state == null) {
            throw new IllegalStateException("Authentication session/state is missing");
        }
        OIDCIdentityProviderConfig config = getConfig();
        String issuer = required(config.getIssuer(), "Issuer");
        if (!config.isValidateSignature()) {
            throw new IllegalArgumentException("Validate signatures must be enabled for External OIDC PAR");
        }
        if (config.isDisableNonce()) {
            throw new IllegalArgumentException("Disable nonce must be off for External OIDC PAR");
        }
        if (config.isPkceEnabled()) {
            throw new IllegalArgumentException(
                "Turn off Keycloak's built-in PKCE option; External OIDC PAR sends PKCE through PAR (pkce_mode)");
        }
        String parEndpoint = required(value(ExternalIdpParConfig.PAR_ENDPOINT, null), ExternalIdpParConfig.PAR_ENDPOINT);
        if (!ExternalIdpParSupport.isHttpsOrLoopback(parEndpoint)) {
            throw new IllegalArgumentException("PAR endpoint must use https");
        }
        boolean signedRequestObject = ExternalIdpParSupport.usesSignedRequestObject(
            value(ExternalIdpParConfig.PAR_REQUEST_FORMAT, null));
        String signingAlg = value(ExternalIdpParConfig.REQUEST_OBJECT_SIGNING_ALG, "HS256");
        if (signedRequestObject) ExternalIdpParSupport.ensureSupportedSigningAlgorithm(signingAlg);

        String nonce = ExternalIdpParSupport.randomNonce();
        authSession.setClientNote(BROKER_NONCE, nonce);
        String challenge = null;
        if (usesPkce()) {
            String verifier = ExternalIdpParSupport.randomCodeVerifier();
            challenge = ExternalIdpParSupport.s256(verifier);
            authSession.setAuthNote(ExternalIdpParConfig.PKCE_VERIFIER_NOTE, verifier);
        } else {
            authSession.removeAuthNote(ExternalIdpParConfig.PKCE_VERIFIER_NOTE);
        }

        Map<String, String> parameters = ExternalIdpParSupport.authorizationParameters(
            redirectUri, requestedScope(), acrValues, state, nonce, user,
            value(ExternalIdpParConfig.PAR_USER_ATTRIBUTE_ALLOWLIST, null), challenge
        );
        String requestJwt = null;
        if (signedRequestObject) {
            try (VaultStringSecret secret = session.vault().getStringSecret(config.getClientSecret())) {
                requestJwt = ExternalIdpParSupport.createRequestObject(
                    value(ExternalIdpParConfig.REQUEST_AUDIENCE, issuer), config.getClientId(),
                    secret.get().orElse(config.getClientSecret()), signingAlg, parameters
                );
            }
        }
        // Without a request object, the client-authenticated PAR request itself carries every
        // parameter (RFC 9126); the browser still only sees client_id and request_uri.
        String requestUri = pushAuthorizationRequest(
            parEndpoint, ExternalIdpParSupport.parFormParameters(parameters, requestJwt)
        );
        // RFC 9126 section 4: with PAR, the front channel carries only client_id and request_uri.
        String authorizationUrl = required(config.getAuthorizationUrl(), "Authorization URL");
        String location = authorizationUrl + (authorizationUrl.contains("?") ? "&" : "?")
            + "client_id=" + enc(config.getClientId())
            + "&request_uri=" + enc(requestUri);
        return Response.seeOther(URI.create(location)).build();
    }

    private String pushAuthorizationRequest(String parEndpoint, Map<String, String> form) throws IOException {
        OIDCIdentityProviderConfig config = getConfig();
        // SimpleHttp uses Keycloak's truststore, proxy mappings, and response-size limits.
        SimpleHttpRequest request = SimpleHttp.create(session).doPost(parEndpoint);
        form.forEach(request::param);
        if (config.isBasicAuthentication() || config.isBasicAuthenticationUnencoded()) {
            // authenticateTokenRequest() adds client_id itself for the post and JWT methods.
            request.param("client_id", config.getClientId());
        }
        // Same client authentication (and vault secret resolution) as the token request.
        request = authenticateTokenRequest(request);
        try (SimpleHttpResponse response = request.asResponse()) {
            int status = response.getStatus();
            JsonNode body = readJson(response);
            if (status < 200 || status >= 300) {
                throw new IOException("External IdP PAR returned HTTP " + status + " "
                    + ExternalIdpParSupport.describeOAuthError(body));
            }
            return ExternalIdpParSupport.requestUriFrom(body);
        }
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        BrokeredIdentityContext identity = super.getFederatedIdentity(response);
        verifyAcrIfEnforced(idToken(identity), value(ExternalIdpParConfig.ACR_VALUES, null));
        return identity;
    }

    private void verifyAcrIfEnforced(JsonWebToken idToken, String requestedAcrValues) {
        if (Boolean.parseBoolean(value(ExternalIdpParConfig.ENFORCE_ACR, "true"))) {
            ExternalIdpParSupport.verifyAcr(idToken, requestedAcrValues);
        }
    }

    void validateNonLinkingAuthentication(String tokenResponse,
                                          AuthenticationSessionModel authSession,
                                          UserModel expectedUser) {
        BrokeredIdentityContext identity = super.getFederatedIdentity(tokenResponse);
        JsonWebToken idToken = idToken(identity);
        if (idToken == null) throw new IdentityBrokerException("External IdP ID token was not validated");
        // The step may have requested its own acr_values; a missing note falls back to the provider's.
        String requestedAcr = authSession.getAuthNote(ExternalIdpParConfig.NON_LINKING_ACR_NOTE);
        verifyAcrIfEnforced(idToken, requestedAcr == null ? value(ExternalIdpParConfig.ACR_VALUES, null) : requestedAcr);

        // Checked here rather than through preprocessFederatedIdentity() so the
        // "Disable nonce" toggle can never switch it off for this path.
        String expectedNonce = authSession.getClientNote(BROKER_NONCE);
        authSession.removeClientNote(BROKER_NONCE);
        Object nonce = idToken.getOtherClaims().get(OIDCLoginProtocol.NONCE_PARAM);
        if (isBlank(expectedNonce) || !expectedNonce.equals(nonce)) {
            throw new IdentityBrokerException("External IdP ID token nonce does not match the request");
        }

        if (ExternalIdpParConfig.USER_BINDING_DISABLED.equals(
            value(ExternalIdpParConfig.USER_BINDING, ExternalIdpParConfig.USER_BINDING_REQUIRED))) {
            return;
        }
        if (expectedUser == null) {
            throw new IdentityBrokerException("External IdP user binding failed: no Keycloak user is established"
                + " for this step; set Non-linking user binding to disabled for steps that run before a user exists");
        }
        FederatedIdentityModel link = session.users().getFederatedIdentity(
            session.getContext().getRealm(), expectedUser, getConfig().getAlias()
        );
        if (link != null) {
            if (!link.getUserId().equals(idToken.getSubject())) {
                throw new IdentityBrokerException(
                    "External IdP user binding failed: sub does not match the user's linked identity");
            }
            return;
        }
        Object userInfo = identity.getContextData().get(AbstractJsonUserAttributeMapper.CONTEXT_JSON_NODE);
        ExternalIdpParSupport.verifyClaimBinding(
            idToken, userInfo instanceof JsonNode node ? node : null, expectedUser,
            value(ExternalIdpParConfig.USER_BINDING_CLAIMS, null),
            value(ExternalIdpParConfig.USER_BINDING_ATTRIBUTE, null)
        );
    }

    @Override
    public Object callback(RealmModel realm,
                           UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                           EventBuilder event) {
        return new ExternalParEndpoint(callback, realm, event, this);
    }

    public static class ExternalParEndpoint extends OIDCEndpoint {
        private final ExternalOidcParIdentityProvider provider;

        public ExternalParEndpoint(UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                                   RealmModel realm, EventBuilder event,
                                   ExternalOidcParIdentityProvider provider) {
            super(callback, realm, event, provider);
            this.provider = provider;
        }

        @Override
        public SimpleHttpRequest generateTokenRequest(String authorizationCode) {
            SimpleHttpRequest request = super.generateTokenRequest(authorizationCode);
            if (provider.usesPkce()) {
                AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
                String verifier = authSession == null ? null
                    : authSession.getAuthNote(ExternalIdpParConfig.PKCE_VERIFIER_NOTE);
                if (isBlank(verifier)) {
                    throw new IdentityBrokerException("PKCE verifier is missing from the authentication session");
                }
                request.param("code_verifier", verifier);
            }
            return request;
        }

        @Override
        @GET
        public Response authResponse(
            @QueryParam(OAUTH2_PARAMETER_STATE) String state,
            @QueryParam(OAUTH2_PARAMETER_CODE) String authorizationCode,
            @QueryParam(OAuth2Constants.ERROR) String error,
            @QueryParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {
            if (state == null || !isNonLinkingCallback(state)) {
                if (error != null) provider.logExternalAuthenticationFailure(error, errorDescription);
                // Unmodified native broker callback (first-broker-login / account linking).
                return super.authResponse(state, authorizationCode, error, errorDescription);
            }
            AuthenticationSessionModel authSession;
            try {
                authSession = callback.getAndVerifyAuthenticationSession(state);
            } catch (WebApplicationException e) {
                return e.getResponse();
            }
            session.getContext().setAuthenticationSession(authSession);
            if (error != null || authorizationCode == null) {
                provider.logExternalAuthenticationFailure(error, errorDescription);
                authSession.removeAuthNote(ExternalIdpParConfig.PKCE_VERIFIER_NOTE);
                return resumeNonLinkingFlow(authSession, false);
            }
            try {
                String tokenResponse;
                try (SimpleHttpResponse response = generateTokenRequest(authorizationCode).asResponse()) {
                    int status = response.getStatus();
                    tokenResponse = response.asString();
                    if (status < 200 || status >= 300) {
                        throw new IdentityBrokerException("External IdP token endpoint returned HTTP " + status
                            + " " + ExternalIdpParSupport.describeOAuthError(readJson(tokenResponse)));
                    }
                }
                provider.validateNonLinkingAuthentication(tokenResponse, authSession, expectedUser(authSession));
                return resumeNonLinkingFlow(authSession, true);
            } catch (Exception e) {
                logger.errorf("External IdP PAR non-linking callback validation failed: %s: %s",
                    e.getClass().getSimpleName(), ExternalIdpParSupport.safeLogValue(e.getMessage()));
                return resumeNonLinkingFlow(authSession, false);
            } finally {
                authSession.removeAuthNote(ExternalIdpParConfig.PKCE_VERIFIER_NOTE);
            }
        }

        /**
         * Read-only lookup of the auth session the state points at, mirroring the lookup that
         * getAndVerifyAuthenticationSession() performs but without consuming the one-time code.
         * Whenever full verification would succeed, this sees the same session, so a callback
         * is never sent down the native (linking) path by mistake.
         */
        private boolean isNonLinkingCallback(String state) {
            try {
                IdentityBrokerState brokerState = IdentityBrokerState.encoded(state, realm);
                if (brokerState.getClientId() == null || brokerState.getTabId() == null) return false;
                ClientModel client = realm.getClientByClientId(brokerState.getClientId());
                if (client == null) return false;
                AuthenticationSessionModel authSession = new AuthenticationSessionManager(session)
                    .getCurrentAuthenticationSession(realm, client, brokerState.getTabId());
                return authSession != null
                    && Boolean.TRUE.toString().equals(authSession.getAuthNote(ExternalIdpParConfig.NON_LINKING_NOTE))
                    && provider.getConfig().getAlias().equals(
                        authSession.getAuthNote(ExternalIdpParConfig.NON_LINKING_ALIAS_NOTE));
            } catch (RuntimeException e) {
                return false;
            }
        }

        private UserModel expectedUser(AuthenticationSessionModel authSession) {
            String userId = authSession.getAuthNote(ExternalIdpParConfig.NON_LINKING_USER_NOTE);
            if (isBlank(userId)) return null;
            UserModel user = session.users().getUserById(realm, userId);
            if (user == null) throw new IdentityBrokerException("Keycloak user for this step no longer exists");
            return user;
        }

        private Response resumeNonLinkingFlow(AuthenticationSessionModel authSession, boolean success) {
            // The in-flight marker is consumed here; alias/execution/user notes stay for the
            // authenticator to check before it records the result.
            authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_NOTE);
            authSession.setAuthNote(ExternalIdpParConfig.NON_LINKING_RESULT_NOTE, success
                ? ExternalIdpParConfig.NON_LINKING_RESULT_SUCCESS : ExternalIdpParConfig.NON_LINKING_RESULT_FAILURE);
            // Returns to the current flow (browser, registration, ...) rather than callback.error(),
            // which restarts the browser flow and re-triggers this redirect.
            URI location = new AuthenticationFlowURLHelper(
                session, realm, session.getContext().getUri()
            ).getLastExecutionUrl(authSession);
            return Response.seeOther(location).build();
        }
    }

    private void logExternalAuthenticationFailure(String error, String errorDescription) {
        logger.warnf(
            "External IdP authentication failure: error=%s error_description=%s",
            ExternalIdpParSupport.safeLogValue(error),
            ExternalIdpParSupport.safeLogValue(errorDescription)
        );
    }

    private String requestedScope() {
        LinkedHashSet<String> scopes = new LinkedHashSet<>();
        scopes.add("openid");
        String configured = getConfig().getDefaultScope();
        if (isBlank(configured)) {
            scopes.add("profile");
            scopes.add("email");
        } else {
            // Send exactly what the admin configured (plus openid): PingFederate rejects
            // scopes a client is not allowed with invalid_scope.
            for (String scope : configured.trim().split("\\s+")) {
                if (!scope.isBlank()) scopes.add(scope);
            }
        }
        return String.join(" ", scopes);
    }

    private static JsonWebToken idToken(BrokeredIdentityContext identity) {
        Object token = identity.getContextData().get(VALIDATED_ID_TOKEN);
        return token instanceof JsonWebToken jwt ? jwt : null;
    }
    private static JsonNode readJson(SimpleHttpResponse response) {
        try {
            return response.asJson();
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }
    private static JsonNode readJson(String body) {
        try {
            return org.keycloak.util.JsonSerialization.readValue(body, JsonNode.class);
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }
    private static boolean isBlank(String value) { return value == null || value.isBlank(); }
    boolean usesPkce() {
        String mode = value(ExternalIdpParConfig.PKCE_MODE, ExternalIdpParConfig.PKCE_REQUIRED_S256);
        // "optional" and "required_s256" were accepted by earlier versions and keep PKCE on.
        if (ExternalIdpParConfig.PKCE_REQUIRED_S256.equalsIgnoreCase(mode)
            || "required_s256".equalsIgnoreCase(mode) || "optional".equalsIgnoreCase(mode)) {
            return true;
        }
        if (ExternalIdpParConfig.PKCE_DISABLED.equalsIgnoreCase(mode)) return false;
        throw new IllegalArgumentException("Unsupported pkce_mode: " + ExternalIdpParSupport.safeLogValue(mode));
    }
    private String value(String key, String fallback) {
        String value = getConfig().getConfig().get(key);
        return value == null || value.isBlank() ? fallback : value;
    }
    private static String required(String value, String name) {
        if (isBlank(value)) throw new IllegalArgumentException("Missing provider setting: " + name);
        return value;
    }
    private static String enc(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
}
