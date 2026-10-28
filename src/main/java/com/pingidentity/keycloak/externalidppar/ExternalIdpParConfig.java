package com.pingidentity.keycloak.externalidppar;

public final class ExternalIdpParConfig {
    public static final String PROVIDER_ALIAS = "identity_provider_alias";
    public static final String PAR_ENDPOINT = "par_endpoint";
    public static final String REQUEST_AUDIENCE = "request_audience";
    public static final String PAR_REQUEST_FORMAT = "par_request_format";
    public static final String REQUEST_OBJECT_SIGNING_ALG = "request_object_signing_alg";
    public static final String PKCE_MODE = "pkce_mode";
    public static final String ACR_VALUES = "acr_values";
    public static final String ENFORCE_ACR = "enforce_acr";
    public static final String PAR_USER_ATTRIBUTE_ALLOWLIST = "par_user_attribute_allowlist";
    public static final String USER_BINDING = "user_binding";
    public static final String USER_BINDING_CLAIMS = "user_binding_claims";
    public static final String USER_BINDING_ATTRIBUTE = "user_binding_attribute";

    public static final String PAR_REQUEST_FORMAT_SIGNED = "signed-request-object";
    public static final String PAR_REQUEST_FORMAT_PLAIN = "plain-parameters";
    public static final String PKCE_REQUIRED_S256 = "required-S256";
    public static final String PKCE_DISABLED = "disabled";
    public static final String USER_BINDING_REQUIRED = "required";
    public static final String USER_BINDING_DISABLED = "disabled";
    public static final String DEFAULT_USER_BINDING_CLAIMS = "preferred_username,sub";
    public static final String DEFAULT_USER_BINDING_ATTRIBUTE = "username";
    public static final String ALL_ATTRIBUTES = "*";

    public static final String PKCE_VERIFIER_NOTE = "external.idp.par.pkce.verifier";
    public static final String NON_LINKING_NOTE = "external.idp.par.non-linking";
    public static final String NON_LINKING_RESULT_NOTE = "external.idp.par.non-linking.result";
    public static final String NON_LINKING_RESULT_SUCCESS = "success";
    public static final String NON_LINKING_RESULT_FAILURE = "failure";
    public static final String NON_LINKING_ALIAS_NOTE = "external.idp.par.non-linking.alias";
    public static final String NON_LINKING_EXECUTION_NOTE = "external.idp.par.non-linking.execution";
    public static final String NON_LINKING_USER_NOTE = "external.idp.par.non-linking.user";
    public static final String NON_LINKING_ACR_NOTE = "external.idp.par.non-linking.acr_values";

    private ExternalIdpParConfig() {
    }
}
