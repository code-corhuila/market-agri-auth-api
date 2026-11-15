package co.edu.corhuila.marketagri.auth.adapter.out.security;

import co.edu.corhuila.marketagri.auth.application.port.out.AccessTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.ServiceTokens;
import co.edu.corhuila.marketagri.auth.domain.model.ServiceClient;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Signs the access token (ADR-020 point 1): RS256 with the private key of the environment, its
 * {@code kid} in the header, and the claims of D-C3 ({@code sub, role, name, iss, iat, exp}) in
 * seconds. Every service validates it locally with the public half. A service token (ADR-020 point
 * 5) has {@code sub = service:<name>}, {@code role = SERVICE} and no {@code name}.
 */
public final class Rs256AccessTokens implements AccessTokens, ServiceTokens {

    private static final String SERVICE_ROLE = "SERVICE";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

    private final PrivateKey privateKey;
    private final String keyId;
    private final String issuer;

    public Rs256AccessTokens(PrivateKey privateKey, String keyId, String issuer) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        if (keyId == null || keyId.isBlank() || issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("AUTH_JWT_KEY_ID and JWT_ISSUER are required");
        }
        this.keyId = keyId;
        this.issuer = issuer;
    }

    @Override
    public String sign(User user, Instant issuedAt, Instant expiresAt) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", user.id().toString());
        claims.put("role", user.role().name());
        claims.put("name", user.name());
        return signed(claims, issuedAt, expiresAt);
    }

    @Override
    public String signService(ServiceClient client, Instant issuedAt, Instant expiresAt) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", client.subject());
        claims.put("role", SERVICE_ROLE);
        return signed(claims, issuedAt, expiresAt);
    }

    private String signed(Map<String, Object> claims, Instant issuedAt, Instant expiresAt) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "RS256");
        header.put("typ", "JWT");
        header.put("kid", keyId);
        claims.put("iss", issuer);
        claims.put("iat", issuedAt.getEpochSecond());
        claims.put("exp", expiresAt.getEpochSecond());
        String signed = encode(header) + "." + encode(claims);
        return signed + "." + BASE64URL.encodeToString(signature(signed));
    }

    private static String encode(Map<String, Object> part) {
        try {
            return BASE64URL.encodeToString(JSON.writeValueAsBytes(part));
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private byte[] signature(String signed) {
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(privateKey);
            rsa.update(signed.getBytes(StandardCharsets.US_ASCII));
            return rsa.sign();
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("RS256 signing is unavailable", unavailable);
        }
    }
}
