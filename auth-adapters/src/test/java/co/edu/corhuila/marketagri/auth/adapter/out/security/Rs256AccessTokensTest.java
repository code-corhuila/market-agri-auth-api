package co.edu.corhuila.marketagri.auth.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.ServiceClient;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** The access token of E-02: RS256 with the kid of the environment and the claims of D-C3 (ADR-020). */
class Rs256AccessTokensTest {

    private static final KeyPair KEYS = generate();
    private static final Instant IAT = Instant.parse("2026-11-06T15:00:00Z");
    private static final Instant EXP = IAT.plusSeconds(3600);
    private static final User ANA = new User(UUID.fromString("0b6f2c7e-4a51-4c1e-9d0e-2f1c3a7b9e10"),
            "Ana \"La Finca\" Ruiz", Email.of("productor@market-agri.test"), new PasswordHash("x"), Role.PRODUCER);

    private final Rs256AccessTokens tokens = new Rs256AccessTokens(KEYS.getPrivate(), "kid-test", "market-agri-auth");

    private static KeyPair generate() {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static JsonNode part(String token, int index) throws Exception {
        return new ObjectMapper().readTree(Base64.getUrlDecoder().decode(token.split("\\.")[index]));
    }

    @Test
    void theHeaderIsRs256WithTheKidOfTheEnvironment() throws Exception {
        JsonNode header = part(tokens.sign(ANA, IAT, EXP), 0);

        assertThat(header.get("alg").asText()).isEqualTo("RS256");
        assertThat(header.get("typ").asText()).isEqualTo("JWT");
        assertThat(header.get("kid").asText()).isEqualTo("kid-test");
    }

    @Test
    void theClaimsAreThoseOfDC3InSeconds() throws Exception {
        JsonNode claims = part(tokens.sign(ANA, IAT, EXP), 1);

        assertThat(claims.get("sub").asText()).isEqualTo("0b6f2c7e-4a51-4c1e-9d0e-2f1c3a7b9e10");
        assertThat(claims.get("role").asText()).isEqualTo("PRODUCER");
        assertThat(claims.get("name").asText()).isEqualTo("Ana \"La Finca\" Ruiz");
        assertThat(claims.get("iss").asText()).isEqualTo("market-agri-auth");
        assertThat(claims.get("iat").asLong()).isEqualTo(IAT.getEpochSecond());
        assertThat(claims.get("exp").asLong()).isEqualTo(EXP.getEpochSecond());
        assertThat(claims.has("email")).isFalse();
    }

    @Test
    void theSignatureVerifiesWithThePublicHalfAndBreaksWithAnyChange() throws Exception {
        String token = tokens.sign(ANA, IAT, EXP);
        String[] parts = token.split("\\.");

        assertThat(verifies(parts[0] + "." + parts[1], parts[2])).isTrue();
        String tampered = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"sub\":\"otro\",\"role\":\"ADMIN\"}".getBytes(StandardCharsets.UTF_8));
        assertThat(verifies(parts[0] + "." + tampered, parts[2])).isFalse();
    }

    @Test
    void aServiceTokenSaysWhichServiceItIsWithRoleServiceAndNoName() throws Exception {
        String token = tokens.signService(new ServiceClient("workflow"), IAT, EXP);
        JsonNode header = part(token, 0);
        JsonNode claims = part(token, 1);
        String[] parts = token.split("\\.");

        assertThat(header.get("alg").asText()).isEqualTo("RS256");
        assertThat(header.get("kid").asText()).isEqualTo("kid-test");
        assertThat(claims.get("sub").asText()).isEqualTo("service:workflow");
        assertThat(claims.get("role").asText()).isEqualTo("SERVICE");
        assertThat(claims.get("iss").asText()).isEqualTo("market-agri-auth");
        assertThat(claims.get("iat").asLong()).isEqualTo(IAT.getEpochSecond());
        assertThat(claims.get("exp").asLong()).isEqualTo(EXP.getEpochSecond());
        assertThat(claims.has("name")).isFalse();
        assertThat(verifies(parts[0] + "." + parts[1], parts[2])).isTrue();
    }

    @Test
    void theIssuerAndTheKidAreRequired() {
        assertThatThrownBy(() -> new Rs256AccessTokens(KEYS.getPrivate(), " ", "market-agri-auth"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Rs256AccessTokens(KEYS.getPrivate(), "kid-test", ""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static boolean verifies(String signed, String signature) throws Exception {
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initVerify(KEYS.getPublic());
        rsa.update(signed.getBytes(StandardCharsets.US_ASCII));
        return rsa.verify(Base64.getUrlDecoder().decode(signature));
    }
}
