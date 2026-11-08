package co.edu.corhuila.marketagri.auth.app;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.marketagri.auth.application.port.out.RefreshTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import co.edu.corhuila.marketagri.auth.application.port.out.UserRegistrations;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * FR-008 end to end: with AUTH_ADMIN_EMAIL and AUTH_ADMIN_PASSWORD, the service starts with an ADMIN
 * that logs in through E-02 (bcrypt and RS256 real; the users and the refresh tokens in memory, as in
 * AuthLoginTest: these tests run without a database).
 */
@SpringBootTest(properties = {"auth.admin.email=admin@market-agri.co", "auth.admin.password=Admin-de-main-2026"})
@AutoConfigureMockMvc
@Import(AuthInitialAdminTest.InMemoryUsers.class)
class AuthInitialAdminTest extends AuthSpringTest {

    @TestConfiguration
    static class InMemoryUsers {
        final Map<String, User> byEmail = new ConcurrentHashMap<>();

        @Bean
        @Primary
        UserAccounts inMemoryAccounts() {
            return email -> Optional.ofNullable(byEmail.get(email.value()));
        }

        @Bean
        @Primary
        RefreshTokens inMemoryRefreshTokens() {
            return (userId, issuedAt, expiresAt) -> "refresh-" + userId;
        }

        @Bean
        @Primary
        UserRegistrations inMemoryRegistrations() {
            return new UserRegistrations() {
                @Override
                public void add(User user) {
                    byEmail.put(user.email().value(), user);
                }

                @Override
                public boolean claimKey(String idempotencyKey, UUID userId) {
                    return true;
                }

                @Override
                public Optional<User> userForKey(String idempotencyKey) {
                    return Optional.empty();
                }
            };
        }
    }

    @Autowired
    private MockMvc http;

    @Test
    void theInitialAdminLogsIn() throws Exception {
        http.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\": \"admin@market-agri.co\", \"password\": \"Admin-de-main-2026\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.role").value("ADMIN"))
                .andExpect(jsonPath("$.user.name").value("Administración"));
    }
}
