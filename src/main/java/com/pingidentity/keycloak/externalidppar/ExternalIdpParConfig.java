package com.pingidentity.keycloak.externalidppar;

public final class ExternalIdpParConfig {
    public static final String PROVIDER_ALIAS = "identity_provider_alias";
    public static final String PAR_ENDPOINT = "par_endpoint";
    public static final String REQUEST_AUDIENCE = "request_audience";
    public static final String REQUEST_OBJECT_SIGNING_ALG = "request_object_signing_alg";
    public static final String PKCE_MODE = "pkce_mode";
    public static final String ACR_VALUES = "acr_values";
    public static final String PKCE_VERIFIER_NOTE = "external.idp.par.pkce.verifier";
    public static final String NON_LINKING_NOTE = "external.idp.par.non-linking";
    public static final String NON_LINKING_RESULT_NOTE = "external.idp.par.non-linking.result";

    private ExternalIdpParConfig() {
    }
}
