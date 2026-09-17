package com.pingidentity.keycloak.externalidppar;

import org.keycloak.broker.oidc.KeycloakOIDCIdentityProvider;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class ExternalOidcParIdentityProviderFactory extends KeycloakOIDCIdentityProviderFactory {
    public static final String PROVIDER_ID = "external-oidc-par";

    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getName() { return "External OIDC PAR"; }
    @Override public String getHelpText() {
        return "Native OIDC broker provider that sends a signed request through RFC 9126 PAR.";
    }
    @Override
    public KeycloakOIDCIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new ExternalOidcParIdentityProvider(session, new OIDCIdentityProviderConfig(model));
    }
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> properties = new ArrayList<>(super.getConfigProperties());
        properties.add(property(ExternalIdpParConfig.PAR_ENDPOINT, "PAR endpoint",
            ProviderConfigProperty.STRING_TYPE, ""));
        properties.add(property(ExternalIdpParConfig.REQUEST_AUDIENCE,
            "Request-object audience (OIDC issuer)", ProviderConfigProperty.STRING_TYPE, ""));
        properties.add(property(ExternalIdpParConfig.REQUEST_OBJECT_SIGNING_ALG,
            "Request-object signing algorithm", ProviderConfigProperty.STRING_TYPE, "HS256"));
        properties.add(property(ExternalIdpParConfig.PKCE_MODE, "PKCE mode",
            ProviderConfigProperty.STRING_TYPE, "disabled"));
        properties.add(property(ExternalIdpParConfig.ACR_VALUES, "acr_values",
            ProviderConfigProperty.STRING_TYPE, ""));
        return properties;
    }
    private static ProviderConfigProperty property(String name, String label, String type, String defaultValue) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName(name);
        p.setLabel(label);
        p.setType(type);
        p.setDefaultValue(defaultValue);
        return p;
    }
}
