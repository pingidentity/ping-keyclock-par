package com.pingidentity.keycloak.externalidppar;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;

import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RedirectAuthenticatorTest {

    @Test
    void accountLinkingStepFailsAStrayFormPostWithTheErrorPage() {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        LoginFormsProvider form = mock(LoginFormsProvider.class, RETURNS_SELF);
        Response errorPage = mock(Response.class);
        when(context.form()).thenReturn(form);
        when(form.createErrorPage(Response.Status.BAD_GATEWAY)).thenReturn(errorPage);

        new ExternalIdpParRedirectAuthenticator(true).action(context);

        verify(context).failure(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR, errorPage);
    }
}
