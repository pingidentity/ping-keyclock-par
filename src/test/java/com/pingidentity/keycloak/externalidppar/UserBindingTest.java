package com.pingidentity.keycloak.externalidppar;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserBindingTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void preferredUsernameMatchesUsernameIgnoringCase() {
        JsonWebToken token = token("0f6e-uuid");
        token.setOtherClaims("preferred_username", "Alice");
        assertDoesNotThrow(() -> bind(token, null, "preferred_username,sub", "username"));
    }

    @Test
    void differentExternalUserIsRejected() {
        JsonWebToken token = token("mallory");
        token.setOtherClaims("preferred_username", "mallory");
        IdentityBrokerException e = assertThrows(IdentityBrokerException.class,
            () -> bind(token, null, "preferred_username,sub", "username"));
        assertTrue(e.getMessage().contains("preferred_username"));
        assertFalse(e.getMessage().contains("mallory"), "claim values must not be logged");
    }

    @Test
    void firstPresentClaimDecidesWithoutFallingThrough() {
        // sub would match, but preferred_username is present and wrong: must fail.
        JsonWebToken token = token("alice");
        token.setOtherClaims("preferred_username", "mallory");
        assertThrows(IdentityBrokerException.class, () -> bind(token, null, "preferred_username,sub", "username"));
    }

    @Test
    void fallsBackToSubWhenPreferredUsernameIsAbsent() {
        assertDoesNotThrow(() -> bind(token("alice"), null, "preferred_username,sub", "username"));
        assertThrows(IdentityBrokerException.class,
            () -> bind(token("9a1c-uuid"), null, "preferred_username,sub", "username"));
    }

    @Test
    void userInfoIsConsultedWhenTheIdTokenLacksTheClaim() {
        ObjectNode userInfo = JSON.createObjectNode().put("sub", "9a1c-uuid").put("preferred_username", "alice");
        assertDoesNotThrow(() -> bind(token("9a1c-uuid"), userInfo, "preferred_username,sub", "username"));
    }

    @Test
    void missingClaimsFailClosed() {
        IdentityBrokerException e = assertThrows(IdentityBrokerException.class,
            () -> bind(token("alice"), null, "preferred_username", "username"));
        assertTrue(e.getMessage().contains("none of the claims"));
    }

    @Test
    void blankSettingsUseSafeDefaults() {
        assertDoesNotThrow(() -> bind(token("alice"), null, " ", null));
    }

    @Test
    void emailAndCustomAttributes() {
        JsonWebToken token = token("9a1c-uuid");
        token.setOtherClaims("email", "ALICE@example.com");
        assertDoesNotThrow(() -> bind(token, null, "email", "email"));

        UserModel user = alice();
        when(user.getFirstAttribute("pingone_id")).thenReturn("9a1c-uuid");
        assertDoesNotThrow(() -> ExternalIdpParSupport.verifyClaimBinding(token("9a1c-uuid"), null, user, "sub", "pingone_id"));
        assertThrows(IdentityBrokerException.class,
            () -> ExternalIdpParSupport.verifyClaimBinding(token("9A1C-UUID"), null, user, "sub", "pingone_id"));
    }

    @Test
    void lookAlikeNamesDoNotMatchIgnoringCase() {
        // Kelvin sign, long s, dotless i, dotted capital I: each passes String.equalsIgnoreCase.
        String[][] lookAlikes = {{"Kate", "kate"}, {"ſam", "sam"}, {"alıce", "alice"}, {"alİce", "alice"}};
        for (String[] pair : lookAlikes) {
            assertTrue(pair[0].equalsIgnoreCase(pair[1]), "equalsIgnoreCase folds " + pair[0]);
            assertFalse(ExternalIdpParSupport.equalsIgnoringCase(pair[0], pair[1]), pair[0]);
        }
        assertFalse(ExternalIdpParSupport.equalsIgnoringCase("ａlice", "alice"), "fullwidth letters");
        assertTrue(ExternalIdpParSupport.equalsIgnoringCase("ALICE@Example.COM", "alice@example.com"));
        assertTrue(ExternalIdpParSupport.equalsIgnoringCase("Ärger", "ärger"), "accented letters still ignore case");

        JsonWebToken token = token("9a1c-uuid");
        token.setOtherClaims("preferred_username", "alıce");
        assertThrows(IdentityBrokerException.class, () -> bind(token, null, "preferred_username,sub", "username"));
    }

    @Test
    void unverifiedEmailIsRejectedButAMissingFlagIsNot() {
        JsonWebToken token = token("9a1c-uuid");
        token.setOtherClaims("email", "alice@example.com");
        token.setOtherClaims("email_verified", false);
        IdentityBrokerException e = assertThrows(IdentityBrokerException.class, () -> bind(token, null, "email", "email"));
        assertTrue(e.getMessage().contains("email_verified"));

        ObjectNode userInfo = JSON.createObjectNode().put("email", "alice@example.com").put("email_verified", false);
        assertThrows(IdentityBrokerException.class, () -> bind(token("9a1c-uuid"), userInfo, "email", "email"));

        token.setOtherClaims("email_verified", true);
        assertDoesNotThrow(() -> bind(token, null, "email", "email"));
        JsonWebToken noFlag = token("9a1c-uuid");
        noFlag.setOtherClaims("email", "alice@example.com");
        assertDoesNotThrow(() -> bind(noFlag, null, "email", "email"));
        // The flag only concerns the email claim.
        JsonWebToken username = token("9a1c-uuid");
        username.setOtherClaims("preferred_username", "alice");
        username.setOtherClaims("email_verified", false);
        assertDoesNotThrow(() -> bind(username, null, "preferred_username", "username"));
    }

    @Test
    void userWithoutTheBindingAttributeIsRejected() {
        IdentityBrokerException e = assertThrows(IdentityBrokerException.class,
            () -> bind(token("9a1c-uuid"), null, "sub", "pingone_id"));
        assertTrue(e.getMessage().contains("has no value"));
    }

    private static void bind(JsonWebToken token, ObjectNode userInfo, String claims, String attribute) {
        ExternalIdpParSupport.verifyClaimBinding(token, userInfo, alice(), claims, attribute);
    }

    private static JsonWebToken token(String subject) {
        return new JsonWebToken().subject(subject);
    }

    private static UserModel alice() {
        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn("alice");
        when(user.getEmail()).thenReturn("alice@example.com");
        when(user.getId()).thenReturn("kc-user-id");
        return user;
    }
}
