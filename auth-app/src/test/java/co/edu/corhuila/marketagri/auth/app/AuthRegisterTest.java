package co.edu.corhuila.marketagri.auth.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.edu.corhuila.marketagri.auth.application.port.out.UnitOfWork;
import co.edu.corhuila.marketagri.auth.application.port.out.UserRegistrations;
import co.edu.corhuila.marketagri.auth.domain.model.EmailAlreadyRegisteredException;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
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
 * E-01 through HTTP (HU-AUTH-001, D-C32, D-C35): the real use case and bcrypt, with the users and
 * the keys in memory (their SQL is checked by AuthRegistrationsIT against auth-db).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(AuthRegisterTest.InMemoryRegistrations.class)
@ExtendWith(OutputCaptureExtension.class)
class AuthRegisterTest extends AuthSpringTest {

    private static final String PASSWORD = "Comprador123";

    /** user_account and idempotency_key in memory, with the unique email of auth-db. */
    static final class Memory implements UserRegistrations {
        final Map<String, User> byEmail = new ConcurrentHashMap<>();
        final Map<String, UUID> keys = new ConcurrentHashMap<>();

        @Override
        public void add(User user) {
            if (byEmail.putIfAbsent(user.email().value(), user) != null) {
                throw new EmailAlreadyRegisteredException();
            }
        }

        @Override
        public boolean claimKey(String idempotencyKey, UUID userId) {
            return keys.putIfAbsent(idempotencyKey, userId) == null;
        }

        @Override
        public Optional<User> userForKey(String idempotencyKey) {
            UUID id = keys.get(idempotencyKey);
            return byEmail.values().stream().filter(user -> user.id().equals(id)).findFirst();
        }
    }

    @TestConfiguration
    static class InMemoryRegistrations {
        final Memory memory = new Memory();

        @Bean
        @Primary
        UserRegistrations inMemoryUserRegistrations() {
            return memory;
        }

        @Bean
        @Primary
        UnitOfWork inMemoryUnitOfWork() {
            return new UnitOfWork() {
                @Override
                public <T> T inTransaction(Supplier<T> work) {
                    return work.get();
                }
            };
        }
    }

    @Autowired
    private MockMvc http;

    private Memory memory;

    @Autowired
    void inMemory(InMemoryRegistrations registrations) {
        memory = registrations.memory;
    }

    @BeforeEach
    void emptyDatabase() {
        memory.byEmail.clear();
        memory.keys.clear();
    }

    private ResultActions register(String key, String body) throws Exception {
        var request = post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(body);
        return http.perform(key == null ? request : request.header("Idempotency-Key", key));
    }

    private static String body(String email, String password, String role) {
        return "{\"name\": \" Ana Ruiz \", \"email\": \"" + email + "\", \"password\": \"" + password
                + "\", \"role\": \"" + role + "\"}";
    }

    @Test
    void aValidBodyIs201WithTheUserViewAndItsLocationAndNoTokens() throws Exception {
        String created = register("registro-ana-0001", body(" Ana@Finca.CO ", PASSWORD, "PRODUCER"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Ana Ruiz"))
                .andExpect(jsonPath("$.email").value("ana@finca.co"))
                .andExpect(jsonPath("$.role").value("PRODUCER"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andReturn().getResponse().getContentAsString();
        String id = new ObjectMapper().readTree(created).get("id").asText();

        register("otra-llave-0001", "{}").andExpect(status().isBadRequest());
        register("registro-ana-0001", body("ana@finca.co", PASSWORD, "PRODUCER"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Location"))
                .andExpect(jsonPath("$.id").value(id));
        assertThat(memory.byEmail).hasSize(1);
        assertThat(memory.byEmail.get("ana@finca.co").passwordHash().value()).startsWith("$2a$12$");
    }

    @Test
    void theLocationPointsToTheNewUser() throws Exception {
        String location = register("registro-loc-0001", body("loc@finca.co", PASSWORD, "BUYER"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getHeader("Location");

        assertThat(location).isEqualTo("/api/v1/auth/users/" + memory.byEmail.get("loc@finca.co").id());
    }

    @Test
    void adminIs422AndAnUnknownRoleIs400NamingTheRole() throws Exception {
        register("registro-adm-0001", body("admin@finca.co", PASSWORD, "ADMIN"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("ROLE_NOT_ALLOWED"))
                .andExpect(jsonPath("$.message").value("No es posible registrarse con el rol ADMIN."));
        register("registro-adm-0002", body("admin@finca.co", PASSWORD, "SUPERVISOR"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.details[0].field").value("role"));
        assertThat(memory.byEmail).isEmpty();
    }

    @Test
    void anEmailAlreadyRegisteredInAnyCaseIs409() throws Exception {
        register("registro-dup-0001", body("ana@finca.co", PASSWORD, "PRODUCER")).andExpect(status().isCreated());

        register("registro-dup-0002", body("ANA@Finca.co", PASSWORD, "BUYER"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("EMAIL_ALREADY_REGISTERED"))
                .andExpect(jsonPath("$.message").value("El correo ya está registrado."));
        assertThat(memory.byEmail).hasSize(1);
    }

    @Test
    void aMissingOrInvalidKeyAndAShortPasswordAre400NamingTheField() throws Exception {
        register(null, body("ana@finca.co", PASSWORD, "BUYER"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[0].field").value("Idempotency-Key"));
        register("corta", body("ana@finca.co", PASSWORD, "BUYER"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[0].field").value("Idempotency-Key"));
        register("registro-pwd-0001", body("ana@finca.co", "Corta12", "BUYER"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details", hasSize(1)))
                .andExpect(jsonPath("$.details[0].field").value("password"));
        register("registro-pwd-0002", body("no-es-un-correo", PASSWORD, "BUYER"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"));
        assertThat(memory.byEmail).isEmpty();
    }

    @Test
    void neitherThePasswordNorItsHashReachTheLog(CapturedOutput log) throws Exception {
        register("registro-log-0001", body("log@finca.co", "ClaveSecreta-987", "BUYER")).andExpect(status().isCreated());

        assertThat(log.getOut()).contains("User registered");
        assertThat(log.getOut()).doesNotContain("ClaveSecreta-987").doesNotContain("$2a$12$");
    }
}
