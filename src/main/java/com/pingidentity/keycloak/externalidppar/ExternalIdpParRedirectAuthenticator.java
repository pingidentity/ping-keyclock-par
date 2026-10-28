package com.pingidentity.keycloak.externalidppar;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.Authenticator;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
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

            String providerAlias = providerAlias(context);
            if (!accountLinking && completePendingNonLinkingResult(context, authSession, providerAlias, user)) {
                return;
            }

            IdentityProviderModel providerModel = context.getRealm().getIdentityProviderByAlias(providerAlias);
            if (providerModel == null) {
                throw new IllegalArgumentException("Identity provider alias is not configured: " + providerAlias);
            }
            if (!providerModel.isEnabled()) {
                throw new IllegalArgumentException("Identity provider is disabled: " + providerAlias);
            }

            if (accountLinking) {
                redirectThroughNativeBroker(context, providerAlias);
            } else {
                redirectWithoutAccountLinking(context, providerAlias, user);
            }
        } catch (Exception e) {
            LOG.errorf(accountLinking
                ? "External IdP PAR broker handoff failed: %s"
                : "External IdP PAR non-linking handoff failed: %s",
                ExternalIdpParSupport.safeLogValue(e.getMessage()));
            LOG.debug("External IdP PAR handoff failure detail", e);
            fail(context);
        }
    }

    private void redirectThroughNativeBroker(AuthenticationFlowContext context, String providerAlias) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        ExternalIdpParSupport.clearNonLinkingNotes(authSession);
        String accessCode = createAccessCode(context);
        String clientId = authSession.getClient().getClientId();
        String tabId = authSession.getTabId();
        String clientData = AuthenticationProcessor.getClientData(context.getSession(), authSession);
        URI location = Urls.identityProviderAuthnRequest(
            context.getUriInfo().getBaseUri(), providerAlias,
            context.getRealm().getName(), accessCode, clientId, tabId,
            clientData, null
        );
        context.forceChallenge(Response.seeOther(location).build());
    }

    private void redirectWithoutAccountLinking(AuthenticationFlowContext context,
                                               String providerAlias, UserModel user) throws Exception {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        UserAuthenticationIdentityProvider<?> identityProvider =
            IdentityBrokerService.getIdentityProvider(context.getSession(), providerAlias);
        if (!(identityProvider instanceof ExternalOidcParIdentityProvider provider)) {
            throw new IllegalArgumentException("Configured provider is not External OIDC PAR: " + providerAlias);
        }
        ExternalIdpParSupport.clearNonLinkingNotes(authSession);
        String accessCode = createAccessCode(context);
        String clientData = AuthenticationProcessor.getClientData(context.getSession(), authSession);
        IdentityBrokerState state = IdentityBrokerState.decoded(
            accessCode, authSession.getClient().getId(), authSession.getClient().getClientId(),
            authSession.getTabId(), clientData
        );
        String redirectUri = Urls.identityProviderAuthnResponse(
            context.getUriInfo().getBaseUri(), providerAlias, context.getRealm().getName()
        ).toString();
        Response response = provider.performNonLinkingLogin(
            authSession, state, redirectUri, user, stepConfig(context, ExternalIdpParConfig.ACR_VALUES)
        );
        // Set only after PAR succeeded so a failed push leaves no in-flight marker behind. The
        // callback and completePendingNonLinkingResult() bind the result to these values.
        authSession.setAuthNote(ExternalIdpParConfig.NON_LINKING_NOTE, Boolean.TRUE.toString());
        authSession.setAuthNote(ExternalIdpParConfig.NON_LINKING_ALIAS_NOTE, providerAlias);
        authSession.setAuthNote(ExternalIdpParConfig.NON_LINKING_EXECUTION_NOTE, context.getExecution().getId());
        authSession.setAuthNote(ExternalIdpParConfig.NON_LINKING_USER_NOTE, user == null ? "" : user.getId());
        context.forceChallenge(response);
    }

    private String createAccessCode(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        return new ClientSessionCode<>(
            context.getSession(), context.getRealm(), authSession
        ).getOrGenerateCode();
    }

    private boolean completePendingNonLinkingResult(AuthenticationFlowContext context,
                                                    AuthenticationSessionModel authSession,
                                                    String providerAlias, UserModel user) {
        String result = authSession.getAuthNote(ExternalIdpParConfig.NON_LINKING_RESULT_NOTE);
        if (result == null) return false;

        String resultExecution = authSession.getAuthNote(ExternalIdpParConfig.NON_LINKING_EXECUTION_NOTE);
        String resultAlias = authSession.getAuthNote(ExternalIdpParConfig.NON_LINKING_ALIAS_NOTE);
        String resultUser = authSession.getAuthNote(ExternalIdpParConfig.NON_LINKING_USER_NOTE);
        ExternalIdpParSupport.clearNonLinkingNotes(authSession);
        if (!context.getExecution().getId().equals(resultExecution) || !providerAlias.equals(resultAlias)) {
            // A result recorded for another execution or provider never satisfies this one.
            return false;
        }
        String currentUser = user == null ? "" : user.getId();
        if (ExternalIdpParConfig.NON_LINKING_RESULT_SUCCESS.equals(result) && currentUser.equals(resultUser)) {
            context.success();
        } else {
            fail(context);
        }
        return true;
    }

    private static String providerAlias(AuthenticationFlowContext context) {
        String providerAlias = stepConfig(context, ExternalIdpParConfig.PROVIDER_ALIAS);
        if (providerAlias == null || providerAlias.isBlank()) {
            throw new IllegalArgumentException("Missing identity_provider_alias");
        }
        return providerAlias;
    }

    private static String stepConfig(AuthenticationFlowContext context, String key) {
        Map<String, String> values = context.getAuthenticatorConfig() == null
            ? Map.of() : context.getAuthenticatorConfig().getConfig();
        return values.get(key);
    }

    private static void fail(AuthenticationFlowContext context) {
        // An explicit error page: a bare failure would let the flow restart and redirect again.
        Response errorPage = context.form()
            .setError(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR)
            .createErrorPage(Response.Status.BAD_GATEWAY);
        context.failure(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR, errorPage);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        if (accountLinking) return;
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        try {
            UserModel user = context.getUser();
            if (user == null && authSession != null) user = authSession.getAuthenticatedUser();
            if (authSession == null
                || !completePendingNonLinkingResult(context, authSession, providerAlias(context), user)) {
                fail(context);
            }
        } catch (RuntimeException e) {
            LOG.errorf("External IdP PAR non-linking action failed: %s",
                ExternalIdpParSupport.safeLogValue(e.getMessage()));
            fail(context);
        }
    }

    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
    @Override public void close() { }
}
