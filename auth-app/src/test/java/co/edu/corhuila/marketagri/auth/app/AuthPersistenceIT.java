package co.edu.corhuila.marketagri.auth.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

/** The pool against the real schema: auth_app, its search_path and the limits of Anexo C. */
@SpringBootTest
@AutoConfigureMockMvc
class AuthPersistenceIT extends AuthIntegrationTest {

    @Autowired
    private MockMvc http;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void readyIs200WithTheDatabaseUp() throws Exception {
        http.perform(get("/health/ready"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.checks.database").value("UP"));
    }

    @Test
    void connectsAsAuthAppInsideTheAuthSchema() {
        Map<String, Object> session = jdbc.queryForMap("SELECT current_user AS who, current_schema() AS schema");

        assertThat(session).containsEntry("who", "auth_app").containsEntry("schema", "auth");
    }

    @Test
    void theIntegrationDatabaseHasNoSeedUsers() {
        // --contexts=integration: the seeds of auth-db run only in dev and qa (D-20).
        assertThat(jdbc.queryForObject("SELECT count(*) FROM user_account", Long.class)).isZero();
    }

    @Test
    void everyConnectionCarriesTheStatementTimeout() {
        assertThat(jdbc.queryForObject("SHOW statement_timeout", String.class)).isEqualTo("5s");
    }

    @Test
    void aStatementLongerThanTheLimitIsCancelled() {
        assertThatThrownBy(() -> jdbc.execute("SELECT pg_sleep(6)"))
                .isInstanceOf(DataAccessException.class)
                .hasMessageContaining("statement timeout");
    }
}
