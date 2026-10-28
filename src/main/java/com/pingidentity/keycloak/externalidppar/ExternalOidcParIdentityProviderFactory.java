package com.pingidentity.keycloak.externalidppar;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

// Extends the generic OIDC factory, not KeycloakOIDCIdentityProviderFactory: the
// Keycloak-to-Keycloak provider forces access tokens to be validated as JWTs, which
// fails for PingFederate reference (opaque) access tokens.
public class ExternalOidcParIdentityProviderFactory extends OIDCIdentityProviderFactory {
    public static final String PROVIDER_ID = "external-oidc-par";

    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getName() { return "External OIDC PAR"; }
    @Override public String getHelpText() {
        return "Native OIDC broker provider that sends a signed request through RFC 9126 PAR.";
    }
    @Override
    public ExternalOidcParIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new ExternalOidcParIdentityProvider(session, new OIDCIdentityProviderConfig(model));
    }
    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> properties = new ArrayList<>(super.getConfigProperties());
        properties.add(property(ExternalIdpParConfig.PAR_ENDPOINT, "PAR endpoint",
            "RFC 9126 pushed authorization request endpoint. Must be https (loopback hosts excepted).",
            ProviderConfigProperty.STRING_TYPE, ""));
        properties.add(property(ExternalIdpParConfig.REQUEST_AUDIENCE,
            "Request-object audience (OIDC issuer)", "Defaults to the Issuer.",
            ProviderConfigProperty.STRING_TYPE, ""));
        properties.add(list(ExternalIdpParConfig.PAR_REQUEST_FORMAT, "PAR request format",
            "signed-request-object: parameters in a request object signed with the client secret (PingOne). "
                + "plain-parameters: parameters sent directly in the client-authenticated PAR request, with no "
                + "request object (PingFederate, which accepts only RSA/EC-signed request objects).",
            ExternalIdpParConfig.PAR_REQUEST_FORMAT_SIGNED,
            ExternalIdpParConfig.PAR_REQUEST_FORMAT_SIGNED, ExternalIdpParConfig.PAR_REQUEST_FORMAT_PLAIN));
        properties.add(list(ExternalIdpParConfig.REQUEST_OBJECT_SIGNING_ALG,
            "Request-object signing algorithm", "HMAC keyed with the client secret. Ignored for plain-parameters.",
            "HS256", "HS256", "HS384", "HS512"));
        properties.add(list(ExternalIdpParConfig.PKCE_MODE, "PKCE mode", null,
            ExternalIdpParConfig.PKCE_REQUIRED_S256,
            ExternalIdpParConfig.PKCE_REQUIRED_S256, ExternalIdpParConfig.PKCE_DISABLED));
        properties.add(property(ExternalIdpParConfig.ACR_VALUES, "acr_values",
            "Space-separated acr values to request.", ProviderConfigProperty.STRING_TYPE, ""));
        properties.add(property(ExternalIdpParConfig.ENFORCE_ACR, "Require returned acr to match acr_values",
            "When acr_values is set, reject ID tokens whose acr is not one of the requested values.",
            ProviderConfigProperty.BOOLEAN_TYPE, "true"));
        properties.add(property(ExternalIdpParConfig.PAR_USER_ATTRIBUTE_ALLOWLIST,
            "PAR user-attribute allowlist (comma-separated)",
            "User attributes sent as kc_attr_<name> (first value). Blank sends none; * sends all.",
            ProviderConfigProperty.STRING_TYPE, ""));
        properties.add(list(ExternalIdpParConfig.USER_BINDING, "Non-linking user binding",
            "required: the external identity must match the Keycloak user. Use disabled only for steps that run before a user exists.",
            ExternalIdpParConfig.USER_BINDING_REQUIRED,
            ExternalIdpParConfig.USER_BINDING_REQUIRED, ExternalIdpParConfig.USER_BINDING_DISABLED));
        properties.add(property(ExternalIdpParConfig.USER_BINDING_CLAIMS, "User binding claims",
            "Comma-separated ID token/UserInfo claims; the first one present is compared.",
            ProviderConfigProperty.STRING_TYPE, ExternalIdpParConfig.DEFAULT_USER_BINDING_CLAIMS));
        properties.add(property(ExternalIdpParConfig.USER_BINDING_ATTRIBUTE, "User binding attribute",
            "Keycloak user value compared to the claim: username, email, id, or a user attribute name.",
            ProviderConfigProperty.STRING_TYPE, ExternalIdpParConfig.DEFAULT_USER_BINDING_ATTRIBUTE));
        return properties;
    }
    private static ProviderConfigProperty property(String name, String label, String helpText,
                                                   String type, String defaultValue) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName(name);
        p.setLabel(label);
        p.setHelpText(helpText);
        p.setType(type);
        p.setDefaultValue(defaultValue);
        return p;
    }
    private static ProviderConfigProperty list(String name, String label, String helpText,
                                               String defaultValue, String... options) {
        ProviderConfigProperty p = property(name, label, helpText, ProviderConfigProperty.LIST_TYPE, defaultValue);
        p.setOptions(List.of(options));
        return p;
    }
}
