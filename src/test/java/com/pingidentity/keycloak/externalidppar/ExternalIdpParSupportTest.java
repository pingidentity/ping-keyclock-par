package com.pingidentity.keycloak.externalidppar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.keycloak.models.UserModel;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ExternalIdpParSupportTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SECRET_32 = "0123456789abcdef0123456789abcdef";
    private static final String SECRET_64 = SECRET_32 + SECRET_32;

    @Test
    void requestObjectCarriesExpectedClaimsAndValidHs256Signature() throws Exception {
        UserModel user = user();
        String jwt = ExternalIdpParSupport.createRequestObject(
            "https://pf.example.com", "kc-client", SECRET_32, "HS256",
            ExternalIdpParSupport.authorizationParameters(
                "https://kc.example.com/realms/r/broker/pf/endpoint", "openid profile", "mfa",
                "state-1", "nonce-1", user, null, "challenge-1")
        );

        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);
        JsonNode header = decode(parts[0]);
        JsonNode claims = decode(parts[1]);
        assertEquals("HS256", header.get("alg").asText());
        assertEquals("JWT", header.get("typ").asText());
        assertEquals(hmac("HmacSHA256", SECRET_32, parts[0] + "." + parts[1]), parts[2]);

        assertEquals("kc-client", claims.get("iss").asText());
        assertEquals("https://pf.example.com", claims.get("aud").asText());
        assertEquals("kc-client", claims.get("client_id").asText());
        assertEquals("code", claims.get("response_type").asText());
        assertEquals("state-1", claims.get("state").asText());
        assertEquals("nonce-1", claims.get("nonce").asText());
        assertEquals("alice", claims.get("login_hint").asText());
        assertEquals("alice", claims.get("kc_username").asText());
        assertEquals("Alice Smith", claims.get("kc_full_name").asText());
        assertEquals("mfa", claims.get("acr_values").asText());
        assertEquals("challenge-1", claims.get("code_challenge").asText());
        assertEquals("S256", claims.get("code_challenge_method").asText());
        assertTrue(claims.get("jti").asText().length() > 0);
        long iat = claims.get("iat").asLong();
        assertEquals(iat, claims.get("nbf").asLong());
        assertEquals(iat + ExternalIdpParSupport.REQUEST_OBJECT_LIFETIME_SECONDS, claims.get("exp").asLong());
        assertFalse(claims.has("kc_attributes"));
        claims.fieldNames().forEachRemaining(
            name -> assertFalse(name.startsWith("kc_attr_"), "blank allowlist must send no attributes: " + name));
    }

    @Test
    void requestObjectHonorsAttributeAllowlist() throws Exception {
        String jwt = ExternalIdpParSupport.createRequestObject("aud", "client", SECRET_32, "HS256",
            ExternalIdpParSupport.authorizationParameters("https://cb", "openid", null, "s", "n", user(), "department", null));
        JsonNode claims = decode(jwt.split("\\.")[1]);
        assertEquals("Engineering", claims.get("kc_attr_department").asText());
        assertFalse(claims.has("kc_attr_LDAP_ENTRY_DN"));
    }

    @Test
    void requestObjectWithoutUserOmitsLoginHintAndSendsEmptyStandardClaims() throws Exception {
        String jwt = ExternalIdpParSupport.createRequestObject("aud", "client", SECRET_64, "HS512",
            ExternalIdpParSupport.authorizationParameters("https://cb", "openid", null, "s", "n", null, "*", null));
        String[] parts = jwt.split("\\.");
        JsonNode claims = decode(parts[1]);
        assertEquals("HS512", decode(parts[0]).get("alg").asText());
        assertEquals(hmac("HmacSHA512", SECRET_64, parts[0] + "." + parts[1]), parts[2]);
        assertFalse(claims.has("login_hint"));
        assertFalse(claims.has("code_challenge"));
        assertFalse(claims.has("acr_values"));
        assertEquals("", claims.get("kc_username").asText());
        assertEquals("", claims.get("kc_email").asText());
    }

    @Test
    void rejectsShortSecretsAndUnsupportedAlgorithms() {
        Map<String, String> parameters = ExternalIdpParSupport.authorizationParameters(
            "https://cb", "openid", null, "s", "n", null, null, null);
        assertThrows(IllegalArgumentException.class,
            () -> ExternalIdpParSupport.createRequestObject("aud", "client", "short", "HS256", parameters));
        assertThrows(IllegalArgumentException.class,
            () -> ExternalIdpParSupport.createRequestObject("aud", "client", SECRET_32, "HS384", parameters));
        assertThrows(IllegalArgumentException.class,
            () -> ExternalIdpParSupport.createRequestObject("aud", "client", SECRET_64, "RS256", parameters));
        assertThrows(IllegalArgumentException.class, () -> ExternalIdpParSupport.ensureSupportedSigningAlgorithm("none"));
        ExternalIdpParSupport.ensureSupportedSigningAlgorithm("HS384");
    }

    @Test
    void plainParametersCarryTheWholeRequestWithoutARequestObject() throws Exception {
        Map<String, String> form = ExternalIdpParSupport.parFormParameters(
            ExternalIdpParSupport.authorizationParameters("https://cb", "openid profile", "mfa",
                "state-1", "nonce-1", user(), "department", "challenge-1"), null);

        assertFalse(form.containsKey("request"));
        assertFalse(form.containsKey("client_id"), "client_id is added by the client-authentication step");
        assertEquals("code", form.get("response_type"));
        assertEquals("https://cb", form.get("redirect_uri"));
        assertEquals("openid profile", form.get("scope"));
        assertEquals("state-1", form.get("state"));
        assertEquals("nonce-1", form.get("nonce"));
        assertEquals("alice", form.get("login_hint"));
        assertEquals("alice", form.get("kc_username"));
        assertEquals("alice@example.com", form.get("kc_email"));
        assertEquals("Alice", form.get("kc_given_name"));
        assertEquals("Smith", form.get("kc_family_name"));
        assertEquals("Alice Smith", form.get("kc_full_name"));
        assertFalse(form.containsKey("kc_attributes"));
        assertEquals("Engineering", form.get("kc_attr_department"));
        assertFalse(form.containsKey("kc_attr_LDAP_ENTRY_DN"));
        assertEquals("mfa", form.get("acr_values"));
        assertEquals("challenge-1", form.get("code_challenge"));
        assertEquals("S256", form.get("code_challenge_method"));
        assertFalse(form.values().stream().anyMatch(v -> v.contains("uid=alice")), "allowlist must still apply");
    }

    @Test
    void eachAllowlistedAttributeGetsItsOwnParameterWithTheFirstValue() {
        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn("alice");
        when(user.getEmail()).thenReturn("alice@example.com");
        Map<String, List<String>> attributes = new LinkedHashMap<>();
        attributes.put("sms", List.of("+15550100", "+15550199"));
        attributes.put("email", List.of("alice@example.com"));
        attributes.put("empty", List.of());
        attributes.put("unlisted", List.of("x"));
        when(user.getAttributes()).thenReturn(attributes);

        Map<String, String> parameters = ExternalIdpParSupport.authorizationParameters(
            "https://cb", "openid", null, "s", "n", user, "sms,email,empty", null);

        assertEquals("+15550100", parameters.get("kc_attr_sms"));
        assertEquals("alice@example.com", parameters.get("kc_attr_email"));
        assertEquals("alice@example.com", parameters.get("kc_email"), "fixed kc_* parameters are unaffected");
        assertFalse(parameters.containsKey("kc_attr_empty"));
        assertFalse(parameters.containsKey("kc_attr_unlisted"));
    }

    @Test
    void signedFormRepeatsOnlyTheCoreParametersOutsideTheRequestObject() throws Exception {
        Map<String, String> form = ExternalIdpParSupport.parFormParameters(
            ExternalIdpParSupport.authorizationParameters("https://cb", "openid", "mfa",
                "state-1", "nonce-1", user(), "*", "challenge-1"), "signed.request.object");

        assertEquals(List.of("response_type", "redirect_uri", "scope", "state", "login_hint", "acr_values",
            "code_challenge", "code_challenge_method", "request"), List.copyOf(form.keySet()));
        assertEquals("signed.request.object", form.get("request"));
    }

    @Test
    void parRequestFormatDefaultsToSignedAndFailsClosed() {
        assertTrue(ExternalIdpParSupport.usesSignedRequestObject(null));
        assertTrue(ExternalIdpParSupport.usesSignedRequestObject(" "));
        assertTrue(ExternalIdpParSupport.usesSignedRequestObject("signed-request-object"));
        assertFalse(ExternalIdpParSupport.usesSignedRequestObject("plain-parameters"));
        assertThrows(IllegalArgumentException.class, () -> ExternalIdpParSupport.usesSignedRequestObject("none"));
        assertThrows(IllegalArgumentException.class, () -> ExternalIdpParSupport.usesSignedRequestObject("Plain-Parameters"));
    }

    @Test
    void filterAttributesDefaultsToNothing() {
        Map<String, List<String>> attributes = new LinkedHashMap<>();
        attributes.put("department", List.of("Engineering"));
        attributes.put("LDAP_ENTRY_DN", List.of("uid=alice,ou=people"));
        attributes.put("phone", List.of("555-0100"));

        assertTrue(ExternalIdpParSupport.filterAttributes(attributes, null).isEmpty());
        assertTrue(ExternalIdpParSupport.filterAttributes(attributes, "  ").isEmpty());
        assertTrue(ExternalIdpParSupport.filterAttributes(null, "*").isEmpty());
        assertEquals(3, ExternalIdpParSupport.filterAttributes(attributes, " * ").size());
        Map<String, List<String>> subset = ExternalIdpParSupport.filterAttributes(attributes, "department, phone,unknown");
        assertEquals(List.of("department", "phone"), List.copyOf(subset.keySet()));
    }

    @Test
    void s256MatchesRfc7636Example() {
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ExternalIdpParSupport.s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        String verifier = ExternalIdpParSupport.randomCodeVerifier();
        assertEquals(64, verifier.length());
        assertTrue(verifier.matches("[A-Za-z0-9_-]+"));
        assertFalse(verifier.equals(ExternalIdpParSupport.randomCodeVerifier()));
    }

    @Test
    void requestUriIsParsedAndValidated() throws Exception {
        assertEquals("urn:ietf:params:oauth:request_uri:abc",
            ExternalIdpParSupport.requestUriFrom(JSON.readTree(
                "{\"expires_in\":60,\"request_uri\":\"urn:ietf:params:oauth:request_uri:abc\"}")));
        assertThrows(IOException.class, () -> ExternalIdpParSupport.requestUriFrom(null));
        assertThrows(IOException.class, () -> ExternalIdpParSupport.requestUriFrom(JSON.readTree("{}")));
        assertThrows(IOException.class, () -> ExternalIdpParSupport.requestUriFrom(JSON.readTree("{\"request_uri\":7}")));
        assertThrows(IOException.class, () -> ExternalIdpParSupport.requestUriFrom(JSON.readTree("{\"request_uri\":\"a b\"}")));
        assertThrows(IOException.class, () -> ExternalIdpParSupport.requestUriFrom(JSON.readTree(
            "{\"request_uri\":\"" + "x".repeat(ExternalIdpParSupport.MAX_REQUEST_URI_LENGTH + 1) + "\"}")));
        // A decoy key inside another string value must not be picked up.
        assertThrows(IOException.class, () -> ExternalIdpParSupport.requestUriFrom(JSON.readTree(
            "{\"error_description\":\"\\\"request_uri\\\":\\\"evil\\\"\"}")));
    }

    @Test
    void oauthErrorsAndLogValuesAreSanitized() throws Exception {
        assertEquals("error=invalid_request_object error_description=bad  aud",
            ExternalIdpParSupport.describeOAuthError(JSON.readTree(
                "{\"error\":\"invalid_request_object\",\"error_description\":\"bad\\r\\naud\"}")));
        assertEquals("error=<none>", ExternalIdpParSupport.describeOAuthError(null));
        assertEquals("<none>", ExternalIdpParSupport.safeLogValue(null));
        assertEquals("a b c d e", ExternalIdpParSupport.safeLogValue("a\u001Bb c\td‮e"));
        String longValue = ExternalIdpParSupport.safeLogValue("x".repeat(600));
        assertEquals(ExternalIdpParSupport.MAX_LOG_VALUE_LENGTH + 3, longValue.length());
        assertTrue(longValue.endsWith("..."));
    }

    @Test
    void parEndpointMustBeHttpsUnlessLoopback() {
        assertTrue(ExternalIdpParSupport.isHttpsOrLoopback("https://pf.example.com:9031/as/par.oauth2"));
        assertTrue(ExternalIdpParSupport.isHttpsOrLoopback("http://localhost:9031/as/par.oauth2"));
        assertTrue(ExternalIdpParSupport.isHttpsOrLoopback("http://127.0.0.1/par"));
        assertTrue(ExternalIdpParSupport.isHttpsOrLoopback("http://[::1]:9031/par"));
        assertFalse(ExternalIdpParSupport.isHttpsOrLoopback("http://pf.example.com/as/par.oauth2"));
        assertFalse(ExternalIdpParSupport.isHttpsOrLoopback("http://localhost.evil.example/par"));
        assertFalse(ExternalIdpParSupport.isHttpsOrLoopback("ftp://localhost/par"));
        assertFalse(ExternalIdpParSupport.isHttpsOrLoopback("not a url"));
    }

    private static UserModel user() {
        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn("alice");
        when(user.getEmail()).thenReturn("alice@example.com");
        when(user.getFirstName()).thenReturn("Alice");
        when(user.getLastName()).thenReturn("Smith");
        Map<String, List<String>> attributes = new LinkedHashMap<>();
        attributes.put("department", List.of("Engineering"));
        attributes.put("LDAP_ENTRY_DN", List.of("uid=alice,ou=people"));
        when(user.getAttributes()).thenReturn(attributes);
        return user;
    }

    private static JsonNode decode(String part) throws IOException {
        return JSON.readTree(Base64.getUrlDecoder().decode(part));
    }

    private static String hmac(String algorithm, String secret, String input) throws Exception {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), algorithm));
        byte[] signature = mac.doFinal(input.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
    }
}
