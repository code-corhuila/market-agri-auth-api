package co.edu.corhuila.marketagri.auth.app;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.marketagri.auth.application.port.out.UserProfiles;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/**
 * I-07 {@code GET /internal/v1/auth/users/{id}/contact} (ADR-016): the recipient's address of a
 * notice, only for a SERVICE token. The users are in memory (their SQL is checked by
 * AuthAccountsIT against auth-db).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(AuthUserContactTest.InMemoryProfiles.class)
class AuthUserContactTest extends AuthSpringTest {

    private static final String ANA_ID = "0b6f2c7e-4a51-4c1e-9d0e-2f1c3a7b9e10";
    private static final User ANA = new User(UUID.fromString(ANA_ID), "Ana Ruiz", Email.of("productor@market-agri.test"),
            new PasswordHash("$2a$12$yHcEDghcNSsOFt4XSsWEWO0AVS2aUhwG.ZAjAu4hfONWrdvM4lnSC"), Role.PRODUCER);

    @TestConfiguration
    static class InMemoryProfiles {
        @Bean
        @Primary
        UserProfiles inMemoryUserProfiles() {
            return id -> id.equals(ANA.id()) ? Optional.of(ANA) : Optional.empty();
        }
    }

    @Autowired
    private MockMvc http;

    private ResultActions contact(String id, String token) throws Exception {
        return http.perform(get("/internal/v1/auth/users/" + id + "/contact").header("Authorization", "Bearer " + token));
    }

    @Test
    void aServiceGetsTheContactAndNothingElse() throws Exception {
        contact(ANA_ID, TestTokens.service().signed())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(ANA_ID))
                .andExpect(jsonPath("$.email").value("productor@market-agri.test"))
                .andExpect(jsonPath("$.name").value("Ana Ruiz"))
                .andExpect(jsonPath("$.role").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void aUserTokenIsForbiddenEvenForTheUserThemselves() throws Exception {
        for (String role : new String[] {"PRODUCER", "ADMIN"}) {
            contact(ANA_ID, TestTokens.user(role).claim("sub", ANA_ID).signed())
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("FORBIDDEN"));
        }
    }

    @Test
    void anUnknownUserIs404() throws Exception {
        contact(UUID.randomUUID().toString(), TestTokens.service().signed())
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("USER_NOT_FOUND"))
                .andExpect(jsonPath("$.message").value("El usuario no existe."));
    }

    @Test
    void aMalformedIdIs400AndNoTokenIs401() throws Exception {
        contact("no-es-un-uuid", TestTokens.service().signed())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.details[0].field").value("id"));
        http.perform(get("/internal/v1/auth/users/" + ANA_ID + "/contact")).andExpect(status().isUnauthorized());
    }
}
