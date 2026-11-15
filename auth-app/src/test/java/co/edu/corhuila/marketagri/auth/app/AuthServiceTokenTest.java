package co.edu.corhuila.marketagri.auth.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/**
 * I-01 {@code POST /internal/v1/auth/service-token} (HU-PLAT-002, ADR-020 point 5): client credentials
 * in the body, a 30-day SERVICE token for workflow (the client of the test properties), one 401 otherwise.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class AuthServiceTokenTest extends AuthSpringTest {

    private static final String SECRET = "secreto-de-pruebas";
    private static final Base64.Decoder BASE64URL = Base64.getUrlDecoder();

    @Autowired
    private MockMvc http;

    private final ObjectMapper json = new ObjectMapper();

    private ResultActions issue(String body) throws Exception {
        return http.perform(post("/internal/v1/auth/service-token").contentType(MediaType.APPLICATION_JSON)
                .header("X-Correlation-Id", "deploy-workflow-1").content(body));
    }

    private static String body(String clientId, String clientSecret) {
        return "{\"clientId\": \"" + clientId + "\", \"clientSecret\": \"" + clientSecret + "\"}";
    }

    @Test
    void knownCredentialsGetASignedServiceTokenOfThirtyDays() throws Exception {
        JsonNode response = json.readTree(issue(body("workflow", SECRET))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Correlation-Id", "deploy-workflow-1"))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.expiresAt").isNotEmpty())
                .andReturn().getResponse().getContentAsString());
        String[] parts = response.get("accessToken").asText().split("\\.");

        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initVerify(TestKeys.publicKey());
        rsa.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertThat(rsa.verify(BASE64URL.decode(parts[2]))).isTrue();

        JsonNode header = json.readTree(BASE64URL.decode(parts[0]));
        JsonNode claims = json.readTree(BASE64URL.decode(parts[1]));
        assertThat(header.get("kid").asText()).isEqualTo("kid-test");
        assertThat(claims.get("sub").asText()).isEqualTo("service:workflow");
        assertThat(claims.get("role").asText()).isEqualTo("SERVICE");
        assertThat(claims.get("iss").asText()).isEqualTo("market-agri-auth");
        assertThat(claims.has("name")).isFalse();
        long iat = claims.get("iat").asLong();
        assertThat(claims.get("exp").asLong() - iat).isEqualTo(Duration.ofDays(30).toSeconds());
        assertThat(Instant.parse(response.get("expiresAt").asText()).getEpochSecond())
                .isEqualTo(claims.get("exp").asLong());
    }

    @Test
    void aWrongSecretAndAnUnknownClientGiveTheSame401() throws Exception {
        for (String request : new String[] {body("workflow", "otro"), body("worker", SECRET)}) {
            issue(request)
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("INVALID_CLIENT_CREDENTIALS"))
                    .andExpect(jsonPath("$.message").value("Credenciales de servicio inválidas."))
                    .andExpect(jsonPath("$.details", hasSize(0)))
                    .andExpect(jsonPath("$.traceId").value("deploy-workflow-1"));
        }
    }

    @Test
    void anEmptyFieldIs400NamingEachFieldBeforeTheCredentialsAreChecked() throws Exception {
        issue(body("", " "))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.details", hasSize(2)))
                .andExpect(jsonPath("$.details[?(@.field == 'clientId')]").exists())
                .andExpect(jsonPath("$.details[?(@.field == 'clientSecret')]").exists());
        issue("{}").andExpect(status().isBadRequest()).andExpect(jsonPath("$.details", hasSize(2)));
    }

    @Test
    void theLogNamesTheClientButNeverTheSecretNorTheToken(CapturedOutput log) throws Exception {
        String token = json.readTree(issue(body("workflow", SECRET)).andReturn().getResponse().getContentAsString())
                .get("accessToken").asText();
        issue(body("workflow", "ClaveSecreta-987")).andExpect(status().isUnauthorized());

        assertThat(log.getOut()).contains("Service token issued").contains("Service token refused").contains("workflow");
        assertThat(log.getOut()).doesNotContain(SECRET).doesNotContain("ClaveSecreta-987").doesNotContain(token);
    }
}
