package com.pingidentity.keycloak.externalidppar;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class ExternalIdpParAccountLinkingAuthenticatorFactory implements AuthenticatorFactory {
    public static final String ID = "external-idp-par-redirect-link";
    private static final ExternalIdpParRedirectAuthenticator SINGLETON =
        new ExternalIdpParRedirectAuthenticator(true);

    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "External IdP PAR Redirect (Account Linking)"; }
    @Override public String getReferenceCategory() { return "external-idp-par"; }
    @Override public boolean isConfigurable() { return true; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() {
        return "Redirects through an External OIDC PAR provider and returns through Keycloak's native broker callback, allowing first-broker-login and account linking. This ends the flow as the linked user; it is not a step-up check.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() {
        return ExternalIdpParRedirectAuthenticatorFactory.properties();
    }
    @Override public Authenticator create(KeycloakSession session) { return SINGLETON; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
