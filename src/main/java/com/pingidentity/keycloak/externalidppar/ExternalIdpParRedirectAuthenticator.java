package com.pingidentity.keycloak.externalidppar;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.net.URI;
import java.util.Map;

public class ExternalIdpParRedirectAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(ExternalIdpParRedirectAuthenticator.class);
    private final boolean accountLinking;

    public ExternalIdpParRedirectAuthenticator(boolean accountLinking) {
        this.accountLinking = accountLinking;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            if (authSession == null || authSession.getClient() == null) {
                throw new IllegalStateException("Authentication session or client is missing");
            }
            UserModel user = context.getUser();
            if (user == null) user = authSession.getAuthenticatedUser();

            if (!accountLinking && completePendingNonLinkingResult(context, authSession)) {
                return;
            }

            Map<String, String> values = context.getAuthenticatorConfig() == null
                ? Map.of() : context.getAuthenticatorConfig().getConfig();
            String providerAlias = values.get(ExternalIdpParConfig.PROVIDER_ALIAS);
            if (providerAlias == null || providerAlias.isBlank()) {
                throw new IllegalArgumentException("Missing identity_provider_alias");
            }
            if (context.getRealm().getIdentityProviderByAlias(providerAlias) == null) {
                throw new IllegalArgumentException("Identity provider alias is not configured: " + providerAlias);
            }

            if (accountLinking) {
                redirectThroughNativeBroker(context, providerAlias);
            } else {
                redirectWithoutAccountLinking(context, providerAlias, user);
            }
        } catch (Exception e) {
            LOG.error(accountLinking
                ? "External IdP PAR broker handoff failed"
                : "External IdP PAR non-linking handoff failed", e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    private void redirectThroughNativeBroker(AuthenticationFlowContext context, String providerAlias) {
        String accessCode = createAccessCode(context);
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String clientId = authSession.getClient().getClientId();
        String tabId = authSession.getTabId();
        String clientData = clientData(context);
        URI location = Urls.identityProviderAuthnRequest(
            context.getUriInfo().getBaseUri(), providerAlias,
            context.getRealm().getName(), accessCode, clientId, tabId,
            clientData, null
        );
        context.forceChallenge(Response.seeOther(location).build());
    }

    private void redirectWithoutAccountLinking(AuthenticationFlowContext context,
                                               String providerAlias, UserModel user) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String accessCode = createAccessCode(context);
        String clientData = clientData(context);
        IdentityBrokerState state = IdentityBrokerState.decoded(
            accessCode, authSession.getClient().getId(), authSession.getClient().getClientId(),
            authSession.getTabId(), clientData
        );
        UserAuthenticationIdentityProvider<?> identityProvider =
            IdentityBrokerService.getIdentityProvider(context.getSession(), providerAlias);
        if (!(identityProvider instanceof ExternalOidcParIdentityProvider provider)) {
            throw new IllegalArgumentException("Configured provider is not External OIDC PAR: " + providerAlias);
        }
        authSession.setAuthNote(ExternalIdpParConfig.NON_LINKING_NOTE, Boolean.TRUE.toString());
        authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_RESULT_NOTE);
        String redirectUri = Urls.identityProviderAuthnResponse(
            context.getUriInfo().getBaseUri(), providerAlias, context.getRealm().getName()
        ).toString();
        Response response = provider.performNonLinkingLogin(
            authSession, state, redirectUri, user
        );
        context.forceChallenge(response);
    }

    private String createAccessCode(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        return new ClientSessionCode<>(
            context.getSession(), context.getRealm(), authSession
        ).getOrGenerateCode();
    }

    private String clientData(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String sessionClientData = authSession.getClientNote("client_data");
        String requestClientData = context.getHttpRequest().getUri().getQueryParameters()
            .getFirst("client_data");
        return sessionClientData == null || sessionClientData.isBlank()
            ? requestClientData : sessionClientData;
    }

    private boolean completePendingNonLinkingResult(AuthenticationFlowContext context,
                                                    AuthenticationSessionModel authSession) {
        String result = authSession.getAuthNote(ExternalIdpParConfig.NON_LINKING_RESULT_NOTE);
        if (result == null) return false;

        authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_NOTE);
        authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_RESULT_NOTE);
        if ("success".equals(result)) {
            context.success();
        } else {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
        return true;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        if (accountLinking) return;
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if (authSession == null || !completePendingNonLinkingResult(context, authSession)) {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
    @Override public void close() { }
}
