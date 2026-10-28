package com.pingidentity.keycloak.externalidppar;

import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AcrCheckTest {

    @Test
    void nothingToEnforceWithoutRequestedValues() {
        assertDoesNotThrow(() -> ExternalIdpParSupport.verifyAcr(token(null), null));
        assertDoesNotThrow(() -> ExternalIdpParSupport.verifyAcr(token("pwd"), " "));
    }

    @Test
    void returnedAcrMustBeOneOfTheRequestedValues() {
        assertDoesNotThrow(() -> ExternalIdpParSupport.verifyAcr(token("Multi_Factor"), "Multi_Factor"));
        assertDoesNotThrow(() -> ExternalIdpParSupport.verifyAcr(token("urn:mfa:otp"), "urn:mfa:push  urn:mfa:otp"));
        assertThrows(IdentityBrokerException.class,
            () -> ExternalIdpParSupport.verifyAcr(token("Single_Factor"), "Multi_Factor"));
        assertThrows(IdentityBrokerException.class,
            () -> ExternalIdpParSupport.verifyAcr(token("multi_factor"), "Multi_Factor"));
    }

    @Test
    void missingOrNonStringAcrFailsClosed() {
        assertThrows(IdentityBrokerException.class, () -> ExternalIdpParSupport.verifyAcr(token(null), "mfa"));
        assertThrows(IdentityBrokerException.class, () -> ExternalIdpParSupport.verifyAcr(null, "mfa"));
        JsonWebToken numeric = new JsonWebToken();
        numeric.setOtherClaims("acr", 2);
        assertThrows(IdentityBrokerException.class, () -> ExternalIdpParSupport.verifyAcr(numeric, "2"));
    }

    @Test
    void stepAcrValuesReplaceTheProvidersWhenSet() {
        assertEquals("sms", ExternalIdpParSupport.effectiveAcrValues(" sms ", "urn:acme:mfa"));
        assertEquals("urn:acme:mfa", ExternalIdpParSupport.effectiveAcrValues(" ", "urn:acme:mfa"));
        assertEquals("urn:acme:mfa", ExternalIdpParSupport.effectiveAcrValues(null, "urn:acme:mfa"));
        assertNull(ExternalIdpParSupport.effectiveAcrValues(null, null));
    }

    @Test
    void anotherMethodsAcrDoesNotSatisfyTheStep() {
        String requested = ExternalIdpParSupport.effectiveAcrValues("sms", "email");
        assertDoesNotThrow(() -> ExternalIdpParSupport.verifyAcr(token("sms"), requested));
        assertThrows(IdentityBrokerException.class, () -> ExternalIdpParSupport.verifyAcr(token("email"), requested));
    }

    @Test
    void requestedAcrNoteIsClearedWithTheOtherNonLinkingNotes() {
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        ExternalIdpParSupport.clearNonLinkingNotes(authSession);
        verify(authSession).removeAuthNote(ExternalIdpParConfig.NON_LINKING_ACR_NOTE);
    }

    @Test
    void onlyTheNonLinkingStepOffersAnAcrOverride() {
        assertTrue(names(new ExternalIdpParRedirectAuthenticatorFactory().getConfigProperties())
            .contains(ExternalIdpParConfig.ACR_VALUES));
        assertFalse(names(new ExternalIdpParAccountLinkingAuthenticatorFactory().getConfigProperties())
            .contains(ExternalIdpParConfig.ACR_VALUES));
    }

    private static List<String> names(List<ProviderConfigProperty> properties) {
        return properties.stream().map(ProviderConfigProperty::getName).toList();
    }

    private static JsonWebToken token(String acr) {
        JsonWebToken token = new JsonWebToken();
        if (acr != null) token.setOtherClaims("acr", acr);
        return token;
    }
}
