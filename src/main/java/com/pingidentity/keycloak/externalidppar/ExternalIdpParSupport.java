package com.pingidentity.keycloak.externalidppar;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.regex.Pattern;

public final class ExternalIdpParSupport {
    static final int REQUEST_OBJECT_LIFETIME_SECONDS = 300;
    static final int MAX_LOG_VALUE_LENGTH = 512;
    static final int MAX_REQUEST_URI_LENGTH = 2048;
    static final String ATTRIBUTE_PARAMETER_PREFIX = "kc_attr_";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern UNSAFE_LOG_CHARS = Pattern.compile("[\\p{Cc}\\p{Cf}\\u2028\\u2029]");
    private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "::1", "[::1]");
    private static final Set<String> REPEATED_OUTSIDE_REQUEST_OBJECT = Set.of(
        "response_type", "redirect_uri", "scope", "state", "login_hint", "acr_values",
        "code_challenge", "code_challenge_method");

    private ExternalIdpParSupport() { }

    /**
     * The authorization request Keycloak sends: the claims of the signed request object, or the
     * form parameters of a plain PAR request. client_id is left to the caller.
     */
    public static Map<String, String> authorizationParameters(String redirectUri, String scope,
                                                              String acrValues, String state, String nonce,
                                                              UserModel user, String attributeAllowlist,
                                                              String codeChallenge) {
        String username = user == null ? "" : nullToEmpty(user.getUsername());
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("response_type", "code");
        parameters.put("redirect_uri", redirectUri);
        parameters.put("scope", scope);
        parameters.put("state", state);
        parameters.put("nonce", nonce);
        if (!isBlank(username)) parameters.put("login_hint", username);
        parameters.put("kc_username", username);
        parameters.put("kc_email", user == null ? "" : nullToEmpty(user.getEmail()));
        parameters.put("kc_given_name", user == null ? "" : nullToEmpty(user.getFirstName()));
        parameters.put("kc_family_name", user == null ? "" : nullToEmpty(user.getLastName()));
        parameters.put("kc_full_name", user == null ? "" : join(user.getFirstName(), user.getLastName()));
        // One parameter per allowlisted attribute (first value) so the IdP can track it directly.
        // The kc_attr_ prefix keeps names like "email" from colliding with the fixed kc_* parameters.
        filterAttributes(user == null ? null : user.getAttributes(), attributeAllowlist).forEach((name, values) -> {
            String first = values == null || values.isEmpty() ? null : values.get(0);
            if (first != null) parameters.put(ATTRIBUTE_PARAMETER_PREFIX + name, first);
        });
        if (!isBlank(acrValues)) parameters.put("acr_values", acrValues);
        if (!isBlank(codeChallenge)) {
            parameters.put("code_challenge", codeChallenge);
            parameters.put("code_challenge_method", "S256");
        }
        return parameters;
    }

    public static String createRequestObject(String requestAudience, String clientId, String clientSecret,
                                             String signingAlgorithm, Map<String, String> parameters) {
        ensureHmacSecretLength(clientSecret, signingAlgorithm);
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", clientId);
        claims.put("aud", requestAudience);
        claims.put("client_id", clientId);
        claims.putAll(parameters);
        claims.put("iat", now);
        claims.put("nbf", now);
        claims.put("exp", now + REQUEST_OBJECT_LIFETIME_SECONDS);
        claims.put("jti", UUID.randomUUID().toString());

        byte[] key = clientSecret.getBytes(StandardCharsets.UTF_8);
        JWSBuilder.EncodingBuilder jws = new JWSBuilder().type("JWT").jsonContent(claims);
        return switch (signingAlgorithm) {
            case "HS256" -> jws.hmac256(key);
            case "HS384" -> jws.hmac384(key);
            case "HS512" -> jws.hmac512(key);
            default -> throw unsupportedAlgorithm(signingAlgorithm);
        };
    }

    /**
     * PAR form parameters. With a request object, the core parameters are repeated outside it
     * (the IdP uses the signed values). Without one, every parameter is sent directly.
     */
    public static Map<String, String> parFormParameters(Map<String, String> parameters, String requestObject) {
        Map<String, String> form = new LinkedHashMap<>();
        parameters.forEach((name, value) -> {
            if (requestObject == null || REPEATED_OUTSIDE_REQUEST_OBJECT.contains(name)) form.put(name, value);
        });
        if (requestObject != null) form.put("request", requestObject);
        return form;
    }

    /** true for a signed request object (the default), false for plain PAR parameters; fails closed otherwise. */
    public static boolean usesSignedRequestObject(String parRequestFormat) {
        if (isBlank(parRequestFormat) || ExternalIdpParConfig.PAR_REQUEST_FORMAT_SIGNED.equals(parRequestFormat)) {
            return true;
        }
        if (ExternalIdpParConfig.PAR_REQUEST_FORMAT_PLAIN.equals(parRequestFormat)) return false;
        throw new IllegalArgumentException("Unsupported par_request_format: " + safeLogValue(parRequestFormat));
    }

    /** Blank allowlist sends no attributes, {@code *} sends all, otherwise only the listed names. */
    public static Map<String, List<String>> filterAttributes(Map<String, List<String>> attributes, String allowlist) {
        Map<String, List<String>> filtered = new TreeMap<>();
        if (attributes == null || isBlank(allowlist)) return filtered;
        if (ExternalIdpParConfig.ALL_ATTRIBUTES.equals(allowlist.trim())) {
            filtered.putAll(attributes);
            return filtered;
        }
        Set<String> allowed = splitList(allowlist, ",");
        attributes.forEach((name, values) -> {
            if (allowed.contains(name)) filtered.put(name, values);
        });
        return filtered;
    }

    public static String requestUriFrom(JsonNode parResponse) throws IOException {
        JsonNode node = parResponse == null ? null : parResponse.get("request_uri");
        String value = node == null || !node.isTextual() ? null : node.asText();
        if (isBlank(value) || value.length() > MAX_REQUEST_URI_LENGTH
            || value.chars().anyMatch(c -> Character.isWhitespace(c) || Character.isISOControl(c))) {
            throw new IOException("External IdP PAR response did not contain a valid request_uri");
        }
        return value;
    }

    public static String describeOAuthError(JsonNode body) {
        if (body == null || !body.isObject()) return "error=<none>";
        return "error=" + safeLogValue(text(body, "error"))
            + " error_description=" + safeLogValue(text(body, "error_description"));
    }

    public static void verifyAcr(JsonWebToken idToken, String requestedAcrValues) {
        if (isBlank(requestedAcrValues)) return;
        Object acr = idToken == null ? null : idToken.getOtherClaims().get("acr");
        Set<String> requested = splitList(requestedAcrValues, " ");
        if (!(acr instanceof String value) || !requested.contains(value)) {
            throw new IdentityBrokerException("External IdP returned acr " + safeLogValue(acr == null ? null : acr.toString())
                + " which is not one of the requested acr_values " + requested);
        }
    }

    /**
     * Compares the first configured claim present in the ID token (then UserInfo) with the
     * Keycloak user's value. Claim values are never included in the exception message.
     */
    public static void verifyClaimBinding(JsonWebToken idToken, JsonNode userInfo, UserModel user,
                                          String claimNames, String userAttribute) {
        Set<String> claims = splitList(isBlank(claimNames)
            ? ExternalIdpParConfig.DEFAULT_USER_BINDING_CLAIMS : claimNames, ",");
        String attribute = isBlank(userAttribute)
            ? ExternalIdpParConfig.DEFAULT_USER_BINDING_ATTRIBUTE : userAttribute.trim();
        for (String claim : claims) {
            String claimValue = claimValue(idToken, userInfo, claim);
            if (isBlank(claimValue)) continue;
            String userValue = userValue(user, attribute);
            if (isBlank(userValue)) {
                throw new IdentityBrokerException(
                    "External IdP user binding failed: Keycloak user has no value for '" + attribute + "'");
            }
            boolean caseInsensitive = "username".equals(attribute) || "email".equals(attribute);
            boolean matches = caseInsensitive ? claimValue.equalsIgnoreCase(userValue) : claimValue.equals(userValue);
            if (!matches) {
                throw new IdentityBrokerException("External IdP user binding failed: claim '" + claim
                    + "' does not match Keycloak user '" + attribute + "'");
            }
            return;
        }
        throw new IdentityBrokerException(
            "External IdP user binding failed: none of the claims " + claims + " were returned");
    }

    public static void clearNonLinkingNotes(AuthenticationSessionModel authSession) {
        if (authSession == null) return;
        authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_NOTE);
        authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_RESULT_NOTE);
        authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_ALIAS_NOTE);
        authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_EXECUTION_NOTE);
        authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_USER_NOTE);
        authSession.removeAuthNote(ExternalIdpParConfig.NON_LINKING_ACR_NOTE);
    }

    /** A step's own acr_values replace the provider's; a blank step value keeps the provider's. */
    public static String effectiveAcrValues(String stepAcrValues, String providerAcrValues) {
        return isBlank(stepAcrValues) ? providerAcrValues : stepAcrValues.trim();
    }

    public static String randomNonce() { return UUID.randomUUID().toString(); }

    public static String randomCodeVerifier() {
        byte[] bytes = new byte[48];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String s256(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    public static boolean isHttpsOrLoopback(String url) {
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();
            if ("https".equalsIgnoreCase(scheme)) return uri.getHost() != null;
            return "http".equalsIgnoreCase(scheme) && uri.getHost() != null
                && LOOPBACK_HOSTS.contains(uri.getHost().toLowerCase());
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public static String safeLogValue(String value) {
        if (value == null || value.isBlank()) return "<none>";
        String normalized = UNSAFE_LOG_CHARS.matcher(value).replaceAll(" ");
        if (normalized.length() <= MAX_LOG_VALUE_LENGTH) return normalized;
        return normalized.substring(0, MAX_LOG_VALUE_LENGTH) + "...";
    }

    public static void ensureSupportedSigningAlgorithm(String value) {
        if (!List.of("HS256", "HS384", "HS512").contains(value)) throw unsupportedAlgorithm(value);
    }

    static void ensureHmacSecretLength(String secret, String algorithm) {
        int minimumBytes = switch (algorithm) {
            case "HS256" -> 32;
            case "HS384" -> 48;
            case "HS512" -> 64;
            default -> throw unsupportedAlgorithm(algorithm);
        };
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < minimumBytes) {
            throw new IllegalArgumentException(
                "Client secret is too short for " + algorithm + " request-object signing; minimum is "
                    + minimumBytes + " UTF-8 bytes"
            );
        }
    }

    static Set<String> splitList(String value, String separator) {
        Set<String> items = new LinkedHashSet<>();
        if (value == null) return items;
        Arrays.stream(value.split(Pattern.quote(separator) + "|\\s+"))
            .map(String::trim).filter(s -> !s.isEmpty()).forEach(items::add);
        return items;
    }

    private static String claimValue(JsonWebToken idToken, JsonNode userInfo, String claim) {
        if (idToken != null) {
            Object value = "sub".equals(claim) ? idToken.getSubject() : idToken.getOtherClaims().get(claim);
            if (value instanceof String || value instanceof Number || value instanceof Boolean) {
                String text = value.toString();
                if (!text.isBlank()) return text;
            }
        }
        if (userInfo != null && userInfo.isObject()) {
            JsonNode node = userInfo.get(claim);
            if (node != null && node.isValueNode() && !node.isNull()) return node.asText();
        }
        return null;
    }

    private static String userValue(UserModel user, String attribute) {
        return switch (attribute) {
            case "username" -> user.getUsername();
            case "email" -> user.getEmail();
            case "id" -> user.getId();
            default -> user.getFirstAttribute(attribute);
        };
    }

    private static String text(JsonNode body, String field) {
        JsonNode node = body.get(field);
        return node == null || !node.isValueNode() ? null : node.asText();
    }
    private static IllegalArgumentException unsupportedAlgorithm(String value) {
        return new IllegalArgumentException("Unsupported request_object_signing_alg: " + value);
    }
    private static String nullToEmpty(String value) { return value == null ? "" : value; }
    private static String join(String first, String last) { return (nullToEmpty(first) + " " + nullToEmpty(last)).trim(); }
    private static boolean isBlank(String value) { return value == null || value.isBlank(); }
}
