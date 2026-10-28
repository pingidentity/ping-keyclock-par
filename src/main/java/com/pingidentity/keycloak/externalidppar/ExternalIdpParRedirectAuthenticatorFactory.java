package com.pingidentity.keycloak.externalidppar;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class ExternalIdpParRedirectAuthenticatorFactory implements AuthenticatorFactory {
    public static final String ID = "external-idp-par-redirect";
    private static final ExternalIdpParRedirectAuthenticator SINGLETON =
        new ExternalIdpParRedirectAuthenticator(false);

    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "External IdP PAR Redirect"; }
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
        return "Redirects through an External OIDC PAR provider and resumes the current flow without creating or linking a broker identity. The external identity must match the Keycloak user unless user binding is disabled on the provider.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> properties = properties();
        ProviderConfigProperty acrValues = property(ExternalIdpParConfig.ACR_VALUES,
            "acr_values for this step", ProviderConfigProperty.STRING_TYPE, "");
        acrValues.setHelpText("Space-separated acr values this step requests instead of the provider's acr_values, "
            + "for example email or sms. Blank uses the provider's. Require returned acr to match checks the "
            + "returned acr against these values.");
        properties.add(acrValues);
        return properties;
    }
    static List<ProviderConfigProperty> properties() {
        List<ProviderConfigProperty> properties = new ArrayList<>();
        properties.add(property(ExternalIdpParConfig.PROVIDER_ALIAS,
            "Identity provider alias", ProviderConfigProperty.STRING_TYPE, ""));
        return properties;
    }
    private static ProviderConfigProperty property(String name, String label, String type, String defaultValue) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName(name); p.setLabel(label); p.setType(type); p.setDefaultValue(defaultValue);
        return p;
    }
    @Override public Authenticator create(KeycloakSession session) { return SINGLETON; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
}
