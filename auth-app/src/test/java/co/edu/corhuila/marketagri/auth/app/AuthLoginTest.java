package co.edu.corhuila.marketagri.auth.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.marketagri.auth.application.port.out.RefreshTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/**
 * E-02 through HTTP (HU-AUTH-002, D-C3): the real use case, bcrypt and RS256, with the users and the
 * refresh tokens in memory (their SQL is checked by AuthAccountsIT against auth-db).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(AuthLoginTest.InMemoryAccounts.class)
@ExtendWith(OutputCaptureExtension.class)
class AuthLoginTest extends AuthSpringTest {

    private static final UUID ANA_ID = UUID.fromString("0b6f2c7e-4a51-4c1e-9d0e-2f1c3a7b9e10");
    /** bcrypt cost 12 of Productor123, the development password of the seed (auth-db README). */
    private static final User ANA = new User(ANA_ID, "Ana Ruiz", Email.of("productor@market-agri.test"),
            new PasswordHash("$2a$12$yHcEDghcNSsOFt4XSsWEWO0AVS2aUhwG.ZAjAu4hfONWrdvM4lnSC"), Role.PRODUCER);
    private static final String PASSWORD = "Productor123";

    @TestConfiguration
    static class InMemoryAccounts {
        final List<String> issued = new ArrayList<>();

        @Bean
        @Primary
        UserAccounts inMemoryUserAccounts() {
            return email -> email.equals(ANA.email()) ? Optional.of(ANA) : Optional.empty();
        }

        @Bean
        @Primary
        RefreshTokens inMemoryRefreshTokens() {
            return (userId, issuedAt, expiresAt) -> {
                String token = "refresh-" + issued.size() + "-" + userId;
                issued.add(token);
                return token;
            };
        }
    }

    @Autowired
    private MockMvc http;

    @Autowired
    private InMemoryAccounts memory;

    private final ObjectMapper json = new ObjectMapper();

    @BeforeEach
    void forgetTokens() {
        memory.issued.clear();
    }

    private ResultActions logIn(String body) throws Exception {
        return http.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .header("User-Agent", "pruebas-e2e/1.0").content(body));
    }

    private static String body(String email, String password) {
        return "{\"email\": \"" + email + "\", \"password\": \"" + password + "\"}";
    }

    @Test
    void theRightPasswordAnswers200WithTheAuthResponse() throws Exception {
        logIn(body("productor@market-agri.test", PASSWORD))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").value("refresh-0-" + ANA_ID))
                .andExpect(jsonPath("$.expiresAt").isNotEmpty())
                .andExpect(jsonPath("$.user.id").value(ANA_ID.toString()))
                .andExpect(jsonPath("$.user.name").value("Ana Ruiz"))
                .andExpect(jsonPath("$.user.email").value("productor@market-agri.test"))
                .andExpect(jsonPath("$.user.role").value("PRODUCER"))
                .andExpect(jsonPath("$.user.passwordHash").doesNotExist());
        assertThat(memory.issued).hasSize(1);
    }

    @Test
    void theAccessTokenIsSignedByAuthWithTheClaimsOfDC3() throws Exception {
        JsonNode response = json.readTree(logIn(body("  Productor@Market-Agri.TEST ", PASSWORD))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        String[] parts = response.get("accessToken").asText().split("\\.");

        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initVerify(TestKeys.publicKey());
        rsa.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertThat(rsa.verify(Base64.getUrlDecoder().decode(parts[2]))).isTrue();

        JsonNode header = json.readTree(Base64.getUrlDecoder().decode(parts[0]));
        JsonNode claims = json.readTree(Base64.getUrlDecoder().decode(parts[1]));
        assertThat(header.get("kid").asText()).isEqualTo("kid-test");
        assertThat(claims.get("sub").asText()).isEqualTo(ANA_ID.toString());
        assertThat(claims.get("role").asText()).isEqualTo("PRODUCER");
        assertThat(claims.get("name").asText()).isEqualTo("Ana Ruiz");
        assertThat(claims.get("iss").asText()).isEqualTo("market-agri-auth");
        long iat = claims.get("iat").asLong();
        assertThat(claims.get("exp").asLong() - iat).isEqualTo(Duration.ofMinutes(60).toSeconds());
        assertThat(Instant.parse(response.get("expiresAt").asText()).getEpochSecond())
                .isEqualTo(claims.get("exp").asLong());
    }

    @Test
    void aWrongPasswordAndAnUnknownEmailGiveTheSame401() throws Exception {
        String wrong = logIn(body("productor@market-agri.test", "Otra123"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("Correo o contraseña incorrectos."))
                .andExpect(jsonPath("$.details", hasSize(0)))
                .andReturn().getResponse().getContentAsString();
        String unknown = logIn(body("nadie@market-agri.test", PASSWORD))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        // FR-002: only the traceId differs.
        JsonNode unknownBody = ((ObjectNode) json.readTree(unknown)).without("traceId");
        JsonNode wrongBody = ((ObjectNode) json.readTree(wrong)).without("traceId");
        assertThat(unknownBody).isEqualTo(wrongBody);
        assertThat(memory.issued).isEmpty();
    }

    @Test
    void anEmptyFieldIs400NamingEachField() throws Exception {
        logIn(body("", " "))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.details", hasSize(2)))
                .andExpect(jsonPath("$.details[?(@.field == 'email')]").exists())
                .andExpect(jsonPath("$.details[?(@.field == 'password')]").exists());
        logIn("{}").andExpect(status().isBadRequest()).andExpect(jsonPath("$.details", hasSize(2)));
    }

    @Test
    void aFailureIsLoggedWithTheClientButNeverWithThePassword(CapturedOutput log) throws Exception {
        logIn(body("productor@market-agri.test", "ClaveSecreta-987")).andExpect(status().isUnauthorized());

        // NFR-052: IP, time and user agent of every failure; never the password.
        assertThat(log.getOut()).contains("Login failed").contains("pruebas-e2e/1.0").contains("127.0.0.1");
        assertThat(log.getOut()).doesNotContain("ClaveSecreta-987");
    }
}
