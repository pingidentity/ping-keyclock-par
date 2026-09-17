package com.pingidentity.keycloak.externalidppar;

import com.nimbusds.jose.JOSEException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.Urls;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;

public class ExternalOidcParIdentityProvider extends KeycloakOIDCIdentityProvider {
    private static final String BROKER_NONCE = "BROKER_NONCE";
    private static final int MAX_EXTERNAL_ERROR_LOG_LENGTH = 512;

    public ExternalOidcParIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        return performParLogin(
            request.getAuthenticationSession(), request.getState().getEncoded(),
            request.getRedirectUri(), request.getAuthenticationSession().getAuthenticatedUser()
        );
    }

    public Response performNonLinkingLogin(AuthenticationSessionModel authSession,
                                            IdentityBrokerState state,
                                            String redirectUri,
                                            UserModel user) {
        return performParLogin(authSession, state.getEncoded(), redirectUri, user);
    }

    private Response performParLogin(AuthenticationSessionModel authSession,
                                     String state,
                                     String redirectUri,
                                     UserModel user) {
        try {
            if (authSession == null || state == null) {
                throw new IllegalStateException("Authentication session/state is missing");
            }
            String nonce = ExternalIdpParSupport.randomNonce();
            // Keycloak's inherited OIDC callback and preprocessFederatedIdentity()
            // use this exact client-note key for nonce validation.
            authSession.setClientNote(BROKER_NONCE, nonce);

            String pkceMode = value(ExternalIdpParConfig.PKCE_MODE, "disabled");
            String challenge = null;
            if (usesPkce(pkceMode)) {
                String verifier = ExternalIdpParSupport.randomCodeVerifier();
                challenge = ExternalIdpParSupport.s256(verifier);
                authSession.setAuthNote(ExternalIdpParConfig.PKCE_VERIFIER_NOTE, verifier);
            } else {
                authSession.removeAuthNote(ExternalIdpParConfig.PKCE_VERIFIER_NOTE);
            }

            String scope = requestedScope();
            String signingAlg = value(ExternalIdpParConfig.REQUEST_OBJECT_SIGNING_ALG, "HS256");
            String requestAudience = value(ExternalIdpParConfig.REQUEST_AUDIENCE, getConfig().getIssuer());
            String acrValues = value(ExternalIdpParConfig.ACR_VALUES, null);
            String loginHint = user == null ? null : user.getUsername();
            String requestJwt = ExternalIdpParSupport.createRequestObject(
                requestAudience, getConfig().getClientId(), getConfig().getClientSecret(),
                redirectUri, scope, acrValues, signingAlg, state, nonce, user, challenge
            );
            String requestUri = ExternalIdpParSupport.pushAuthorizationRequest(
                required(ExternalIdpParConfig.PAR_ENDPOINT), getConfig().getClientId(),
                getConfig().getClientSecret(), getConfig().getClientAuthMethod(),
                redirectUri, scope, acrValues, state, requestJwt, challenge, loginHint
            );
            String authorizeUrl = getConfig().getAuthorizationUrl()
                + "?client_id=" + enc(getConfig().getClientId())
                + "&request_uri=" + enc(requestUri)
                + "&state=" + enc(state);
            return Response.seeOther(URI.create(authorizeUrl)).build();
        } catch (IOException | InterruptedException | JOSEException | RuntimeException e) {
            logger.error("Failed to create external IdP PAR request", e);
            return Response.serverError().build();
        }
    }

    public String exchangeAuthorizationCode(String authorizationCode, String redirectUri) throws IOException {
        if (authorizationCode == null || authorizationCode.isBlank()) {
            throw new IdentityBrokerException("Authorization code is missing");
        }
        SimpleHttpRequest request = SimpleHttp.create(session).doPost(getConfig().getTokenUrl())
            .param("code", authorizationCode)
            .param("redirect_uri", redirectUri)
            .param("grant_type", "authorization_code");
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        String verifier = authSession == null ? null
            : authSession.getAuthNote(ExternalIdpParConfig.PKCE_VERIFIER_NOTE);
        if (usesPkce(value(ExternalIdpParConfig.PKCE_MODE, "disabled"))) {
            if (verifier == null || verifier.isBlank()) {
                throw new IdentityBrokerException("PKCE verifier is missing");
            }
            request.param("code_verifier", verifier);
        }
        request = authenticateTokenRequest(request);
        try (SimpleHttpResponse response = request.asResponse()) {
            int status = response.getStatus();
            String body = response.asString();
            if (status < 200 || status >= 400) {
                throw new IdentityBrokerException("External IdP token endpoint returned HTTP " + status);
            }
            return body;
        }
    }

    public void validateNonLinkingAuthentication(String tokenResponse) {
        BrokeredIdentityContext identity = getFederatedIdentity(tokenResponse);
        // This validates the ID-token nonce but intentionally does not pass the
        // context to IdentityBrokerService.authenticated(), so no federated
        // identity is created and no first-broker-login flow is entered.
        preprocessFederatedIdentity(session, session.getContext().getRealm(), identity);
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        BrokeredIdentityContext identity = super.getFederatedIdentity(response);
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        UserModel registeredUser = authSession == null ? null : authSession.getAuthenticatedUser();
        if (registeredUser != null) {
            if (isBlank(identity.getEmail()) && !isBlank(registeredUser.getEmail())) {
                identity.setEmail(registeredUser.getEmail());
            }
            if (isBlank(identity.getFirstName()) && !isBlank(registeredUser.getFirstName())) {
                identity.setFirstName(registeredUser.getFirstName());
            }
            if (isBlank(identity.getLastName()) && !isBlank(registeredUser.getLastName())) {
                identity.setLastName(registeredUser.getLastName());
            }
        }
        return identity;
    }

    @Override
    public Object callback(RealmModel realm,
                           UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                           EventBuilder event) {
        return new ExternalKeycloakEndpoint(callback, realm, event, this);
    }

    public static class ExternalKeycloakEndpoint extends KeycloakEndpoint {
        private final ExternalOidcParIdentityProvider provider;

        public ExternalKeycloakEndpoint(UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                                        RealmModel realm, EventBuilder event,
                                        ExternalOidcParIdentityProvider provider) {
            super(callback, realm, event, provider);
            this.provider = provider;
        }

        @Override
        public SimpleHttpRequest generateTokenRequest(String authorizationCode) {
            SimpleHttpRequest request = super.generateTokenRequest(authorizationCode);
            AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
            String verifier = authSession == null ? null
                : authSession.getAuthNote(ExternalIdpParConfig.PKCE_VERIFIER_NOTE);
            String mode = provider.value(ExternalIdpParConfig.PKCE_MODE, "disabled");
            if (provider.usesPkce(mode)) {
                if (verifier == null || verifier.isBlank()) {
                    throw new IllegalStateException("PKCE verifier missing from native broker authentication session");
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
            if (error != null || errorDescription != null) {
                provider.logExternalAuthenticationFailure(error, errorDescription);
            }
            if (state == null) return super.authResponse(state, authorizationCode, error, errorDescription);
            AuthenticationSessionModel authSession;
            try {
                authSession = callback.getAndVerifyAuthenticationSession(state);
            } catch (Exception e) {
                return super.authResponse(state, authorizationCode, error, errorDescription);
            }
            if (!Boolean.toString(true).equals(
                authSession.getAuthNote(ExternalIdpParConfig.NON_LINKING_NOTE))) {
                return nativeAccountLinkAuthResponse(
                    authSession, state, authorizationCode, error, errorDescription
                );
            }
            session.getContext().setAuthenticationSession(authSession);
            if (error != null || authorizationCode == null) {
                return failNonLinkingFlow(authSession);
            }
            try {
                String tokenResponse = provider.exchangeAuthorizationCode(
                    authorizationCode, callbackRedirectUri()
                );
                provider.validateNonLinkingAuthentication(tokenResponse);
                authSession.removeAuthNote(ExternalIdpParConfig.PKCE_VERIFIER_NOTE);
                return resumeNonLinkingFlow(authSession, true);
            } catch (Exception e) {
                logger.errorf(
                    "External IdP PAR non-linking callback validation failed: %s",
                    e.getClass().getSimpleName()
                );
                return failNonLinkingFlow(authSession);
            }
        }

        private Response nativeAccountLinkAuthResponse(
            AuthenticationSessionModel authSession,
            String state,
            String authorizationCode,
            String error,
            String errorDescription) {
            session.getContext().setAuthenticationSession(authSession);
            if (error != null || authorizationCode == null) {
                // Let Keycloak's native endpoint retain its standard broker error
                // semantics for denied, cancelled, and malformed responses.
                return super.authResponse(state, authorizationCode, error, errorDescription);
            }
            try {
                String tokenResponse = generateTokenRequest(authorizationCode).asString();
                BrokeredIdentityContext federatedIdentity = provider.getFederatedIdentity(tokenResponse);
                federatedIdentity.setIdp(provider);
                federatedIdentity.setAuthenticationSession(authSession);
                return callback.authenticated(federatedIdentity);
            } catch (Exception e) {
                logger.error("External IdP account-link callback validation failed", e);
                return callback.error(provider.getConfig(), Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
        }

        private String callbackRedirectUri() {
            return Urls.identityProviderAuthnResponse(
                session.getContext().getUri().getBaseUri(),
                provider.getConfig().getAlias(), realm.getName()
            ).toString();
        }

        private Response resumeNonLinkingFlow(AuthenticationSessionModel authSession, boolean success) {
            authSession.setAuthNote(
                ExternalIdpParConfig.NON_LINKING_RESULT_NOTE, success ? "success" : "failure"
            );
            URI location = new org.keycloak.services.util.AuthenticationFlowURLHelper(
                session, realm, session.getContext().getUri()
            ).getLastExecutionUrl(authSession);
            return Response.seeOther(location).build();
        }

        private Response failNonLinkingFlow(AuthenticationSessionModel authSession) {
            authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_NOTE);
            authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_RESULT_NOTE);
            authSession.removeAuthNote(ExternalIdpParConfig.PKCE_VERIFIER_NOTE);
            return callback.error(provider.getConfig(), Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }
    }

    private void logExternalAuthenticationFailure(String error, String errorDescription) {
        logger.warnf(
            "External IdP authentication failure: error=%s error_description=%s",
            safeExternalErrorLogValue(error),
            safeExternalErrorLogValue(errorDescription)
        );
    }

    private static String safeExternalErrorLogValue(String value) {
        if (value == null || value.isBlank()) return "<none>";
        String normalized = value.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ');
        if (normalized.length() <= MAX_EXTERNAL_ERROR_LOG_LENGTH) return normalized;
        return normalized.substring(0, MAX_EXTERNAL_ERROR_LOG_LENGTH) + "...";
    }

    private String requestedScope() {
        LinkedHashSet<String> scopes = new LinkedHashSet<>();
        String configured = getConfig().getDefaultScope();
        if (configured != null && !configured.isBlank()) {
            for (String scope : configured.trim().split("\\s+")) {
                if (!scope.isBlank()) scopes.add(scope);
            }
        }
        scopes.add("openid");
        scopes.add("profile");
        scopes.add("email");
        return String.join(" ", scopes);
    }

    private static boolean isBlank(String value) { return value == null || value.isBlank(); }
    private boolean usesPkce(String mode) {
        return "optional".equalsIgnoreCase(mode) || "required-S256".equalsIgnoreCase(mode)
            || "required_s256".equalsIgnoreCase(mode);
    }
    private String value(String key, String fallback) {
        String value = getConfig().getConfig().get(key);
        return value == null || value.isBlank() ? fallback : value;
    }
    private String required(String key) {
        String value = value(key, null);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing provider setting: " + key);
        return value;
    }
    private static String enc(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
}
