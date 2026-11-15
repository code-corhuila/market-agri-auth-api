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
 * E-08 {@code GET /api/v1/auth/users/{id}} (D-C35, the Location of E-01): the user themselves or
 * ADMIN; anyone else, SERVICE included, 403 before existence. The users are in memory (their SQL
 * is checked by AuthAccountsIT against auth-db).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(AuthGetUserTest.InMemoryProfiles.class)
class AuthGetUserTest extends AuthSpringTest {

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

    private ResultActions getUser(String id, String token) throws Exception {
        return http.perform(get("/api/v1/auth/users/" + id).header("Authorization", "Bearer " + token));
    }

    @Test
    void theUserThemselvesGetTheirUserViewWithoutTheHash() throws Exception {
        getUser(ANA_ID, TestTokens.user("PRODUCER").claim("sub", ANA_ID).signed())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(ANA_ID))
                .andExpect(jsonPath("$.name").value("Ana Ruiz"))
                .andExpect(jsonPath("$.email").value("productor@market-agri.test"))
                .andExpect(jsonPath("$.role").value("PRODUCER"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void anAdminGetsAnyUser() throws Exception {
        getUser(ANA_ID, TestTokens.user("ADMIN").signed())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(ANA_ID));
    }

    @Test
    void anotherUserIsForbiddenWhetherTheUserExistsOrNot() throws Exception {
        for (String id : new String[] {ANA_ID, UUID.randomUUID().toString()}) {
            getUser(id, TestTokens.user("BUYER").signed())
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.error").value("FORBIDDEN"))
                    .andExpect(jsonPath("$.message").value("No tiene permisos para realizar esta acción."));
        }
    }

    @Test
    void aServiceTokenIsForbidden() throws Exception {
        getUser(ANA_ID, TestTokens.service().signed())
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("FORBIDDEN"));
    }

    @Test
    void anAdminAskingForAnUnknownUserGets404() throws Exception {
        getUser(UUID.randomUUID().toString(), TestTokens.user("ADMIN").signed())
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("USER_NOT_FOUND"))
                .andExpect(jsonPath("$.message").value("El usuario no existe."));
    }

    @Test
    void aMalformedIdIs400AndNoTokenIs401() throws Exception {
        getUser("no-es-un-uuid", TestTokens.user("ADMIN").signed())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.details[0].field").value("id"));
        http.perform(get("/api/v1/auth/users/" + ANA_ID)).andExpect(status().isUnauthorized());
    }
}
