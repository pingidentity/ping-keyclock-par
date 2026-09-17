package com.pingidentity.keycloak.externalidppar;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.keycloak.models.UserModel;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

public final class ExternalIdpParSupport {
    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10)).build();

    private ExternalIdpParSupport() { }

    public static String createRequestObject(String requestAudience,
                                             String clientId, String clientSecret,
                                             String redirectUri, String scope,
                                             String acrValues, String signingAlgorithm,
                                             String state, String nonce, UserModel user,
                                             String codeChallenge)
        throws JOSEException {
        ensureSupportedSigningAlgorithm(signingAlgorithm);
        ensureHmacSecretLength(clientSecret, signingAlgorithm);
        Instant now = Instant.now();
        String username = user == null ? "" : nullToEmpty(user.getUsername());
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
            .issuer(clientId)
            .audience(requestAudience)
            .claim("client_id", clientId)
            .claim("response_type", "code")
            .claim("redirect_uri", redirectUri)
            .claim("scope", scope)
            .claim("state", state)
            .claim("nonce", nonce)
            .claim("login_hint", username)
            .claim("kc_username", username)
            .claim("kc_email", user == null ? "" : nullToEmpty(user.getEmail()))
            .claim("kc_given_name", user == null ? "" : nullToEmpty(user.getFirstName()))
            .claim("kc_family_name", user == null ? "" : nullToEmpty(user.getLastName()))
            .claim("kc_full_name", user == null ? "" : join(user.getFirstName(), user.getLastName()))
            .claim("kc_attributes", user == null ? Map.of() : user.getAttributes())
            .issueTime(java.util.Date.from(now))
            .expirationTime(java.util.Date.from(now.plusSeconds(300)))
            .jwtID(UUID.randomUUID().toString());
        if (!isBlank(acrValues)) claims.claim("acr_values", acrValues);
        if (!isBlank(codeChallenge)) {
            claims.claim("code_challenge", codeChallenge);
            claims.claim("code_challenge_method", "S256");
        }

        SignedJWT jwt = new SignedJWT(
            new JWSHeader.Builder(signingAlgorithm(signingAlgorithm)).type(JOSEObjectType.JWT).build(),
            claims.build()
        );
        jwt.sign(new MACSigner(clientSecret.getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();
    }

    public static String pushAuthorizationRequest(String parEndpoint, String clientId, String clientSecret,
                                                  String clientAuthMethod, String redirectUri, String scope,
                                                  String acrValues, String state, String requestJwt,
                                                  String codeChallenge, String loginHint)
        throws IOException, InterruptedException {
        StringBuilder form = new StringBuilder()
            .append("client_id=").append(enc(clientId))
            .append("&response_type=code")
            .append("&redirect_uri=").append(enc(redirectUri))
            .append("&scope=").append(enc(scope))
            .append("&state=").append(enc(state))
            .append("&request=").append(enc(requestJwt));
        if (!isBlank(loginHint)) form.append("&login_hint=").append(enc(loginHint));
        if (!isBlank(acrValues)) form.append("&acr_values=").append(enc(acrValues));
        if (!isBlank(codeChallenge)) {
            form.append("&code_challenge=").append(enc(codeChallenge))
                .append("&code_challenge_method=S256");
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(parEndpoint)).timeout(Duration.ofSeconds(20))
            .header("Content-Type", "application/x-www-form-urlencoded");
        if ("client_secret_basic".equals(clientAuthMethod)) {
            String basic = Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
            builder.header("Authorization", "Basic " + basic);
        } else if ("client_secret_post".equals(clientAuthMethod)) {
            form.append("&client_secret=").append(enc(clientSecret));
        } else {
            throw new IllegalArgumentException("Unsupported PAR client authentication method: " + clientAuthMethod);
        }

        HttpResponse<String> response = HTTP.send(
            builder.POST(HttpRequest.BodyPublishers.ofString(form.toString())).build(),
            HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IOException("External IdP PAR returned HTTP " + response.statusCode());
        }
        String requestUri = extractJsonString(response.body(), "request_uri");
        if (isBlank(requestUri)) throw new IOException("External IdP PAR response did not contain request_uri");
        return requestUri;
    }

    public static String randomNonce() { return UUID.randomUUID().toString(); }

    public static String randomCodeVerifier() {
        byte[] bytes = new byte[48];
        new java.security.SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String s256(String verifier) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static String extractJsonString(String json, String name) {
        String marker = "\"" + name + "\"";
        int start = json.indexOf(marker);
        if (start < 0) return null;
        start = json.indexOf(':', start) + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        if (start >= json.length() || json.charAt(start) != '"') return null;
        int end = json.indexOf('"', start + 1);
        return end < 0 ? null : json.substring(start + 1, end);
    }

    private static JWSAlgorithm signingAlgorithm(String value) {
        return switch (value) {
            case "HS256" -> JWSAlgorithm.HS256;
            case "HS384" -> JWSAlgorithm.HS384;
            case "HS512" -> JWSAlgorithm.HS512;
            default -> throw new IllegalArgumentException("Unsupported request_object_signing_alg: " + value);
        };
    }
    private static void ensureSupportedSigningAlgorithm(String value) { signingAlgorithm(value); }
    private static void ensureHmacSecretLength(String secret, String algorithm) {
        int minimumBytes = switch (algorithm) {
            case "HS256" -> 32;
            case "HS384" -> 48;
            case "HS512" -> 64;
            default -> throw new IllegalArgumentException("Unsupported request_object_signing_alg: " + algorithm);
        };
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < minimumBytes) {
            throw new IllegalArgumentException(
                "Client secret is too short for " + algorithm + " request-object signing; minimum is "
                    + minimumBytes + " UTF-8 bytes"
            );
        }
    }
    private static String enc(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private static String nullToEmpty(String value) { return value == null ? "" : value; }
    private static String join(String first, String last) { return (nullToEmpty(first) + " " + nullToEmpty(last)).trim(); }
    private static boolean isBlank(String value) { return value == null || value.isBlank(); }
}
