package co.edu.corhuila.marketagri.auth.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.marketagri.auth.application.port.out.AccessTokens;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

/**
 * E-05 {@code GET /api/v1/auth/jwks} (HU-PLAT-002, RFC 7517): anonymous, the public half of the key
 * auth signs with and its kid, cached ten minutes. Validators keep JWT_PUBLIC_KEY (ADR-020 point 2).
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthJwksTest extends AuthSpringTest {

    private static final int MODULUS_BYTES_OF_RSA_2048 = 256;
    private static final Base64.Decoder BASE64URL = Base64.getUrlDecoder();

    @Autowired
    private MockMvc http;

    @Autowired
    private AccessTokens accessTokens;

    @Test
    void publishesThePublicHalfOfTheSigningKeyWithItsKidAndNoCredential() throws Exception {
        JsonNode jwk = jwk(http.perform(get("/api/v1/auth/jwks"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "public, max-age=600"))
                .andExpect(jsonPath("$.keys", hasSize(1)))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").value("kid-test"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].e").value("AQAB"))
                .andReturn().getResponse().getContentAsString());
        RSAPublicKey expected = (RSAPublicKey) TestKeys.publicKey();

        String n = jwk.get("n").asText();
        assertThat(n).matches("[A-Za-z0-9_-]+");  // base64url without padding
        byte[] modulus = BASE64URL.decode(n);
        assertThat(modulus).hasSize(MODULUS_BYTES_OF_RSA_2048);  // unsigned: no 0x00 sign byte (RFC 7518 §6.3.1)
        assertThat(new BigInteger(1, modulus)).isEqualTo(expected.getModulus());
    }

    @Test
    void thePublishedKeyVerifiesATokenThatAuthSigned() throws Exception {
        Instant now = Instant.parse("2026-11-06T15:00:00Z");
        User ana = new User(UUID.fromString("0b6f2c7e-4a51-4c1e-9d0e-2f1c3a7b9e10"), "Ana Ruiz",
                Email.of("productor@market-agri.test"), new PasswordHash("$2a$12$unused"), Role.PRODUCER);
        String[] token = accessTokens.sign(ana, now, now.plus(Duration.ofMinutes(60))).split("\\.");
        JsonNode jwk = jwk(http.perform(get("/api/v1/auth/jwks")).andReturn().getResponse().getContentAsString());

        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initVerify(publicKeyOf(jwk));
        rsa.update((token[0] + "." + token[1]).getBytes(StandardCharsets.US_ASCII));

        assertThat(rsa.verify(BASE64URL.decode(token[2]))).isTrue();
    }

    private static JsonNode jwk(String body) throws Exception {
        return new ObjectMapper().readTree(body).get("keys").get(0);
    }

    private static PublicKey publicKeyOf(JsonNode jwk) throws Exception {
        BigInteger n = new BigInteger(1, BASE64URL.decode(jwk.get("n").asText()));
        BigInteger e = new BigInteger(1, BASE64URL.decode(jwk.get("e").asText()));
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
    }
}
