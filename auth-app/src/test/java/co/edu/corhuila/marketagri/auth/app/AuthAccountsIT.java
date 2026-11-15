package co.edu.corhuila.marketagri.auth.app;

import static org.assertj.core.api.Assertions.assertThat;

import co.edu.corhuila.marketagri.auth.adapter.out.persistence.OpaqueTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.RefreshTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import co.edu.corhuila.marketagri.auth.application.port.out.UserProfiles;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The SQL of the login against the real tables of auth-db (E-02, D-C2). auth_app has no DELETE,
 * so each test runs in a transaction that is rolled back.
 */
@SpringBootTest
class AuthAccountsIT extends AuthIntegrationTest {

    private static final String HASH = "$2a$12$yHcEDghcNSsOFt4XSsWEWO0AVS2aUhwG.ZAjAu4hfONWrdvM4lnSC";

    @Autowired
    private UserAccounts accounts;

    @Autowired
    private RefreshTokens refreshTokens;

    @Autowired
    private UserProfiles profiles;

    @Autowired
    private JdbcClient jdbc;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private void rolledBack(Runnable test) {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            status.setRollbackOnly();
            test.run();
        });
    }

    private UUID insertUser(String email, Instant deletedAt) {
        UUID id = UUID.randomUUID();
        jdbc.sql("INSERT INTO user_account (id, name, email, password_hash, role, deleted_at)"
                        + " VALUES (:id, 'Ana Ruiz', :email, :hash, 'PRODUCER', :deletedAt)")
                .param("id", id).param("email", email).param("hash", HASH)
                .param("deletedAt", deletedAt == null ? null : java.sql.Timestamp.from(deletedAt))
                .update();
        return id;
    }

    @Test
    void findsAnActiveUserByItsEmail() {
        rolledBack(() -> {
            UUID id = insertUser("ana.it@market-agri.test", null);

            assertThat(accounts.findActiveByEmail(Email.of("ana.it@market-agri.test"))).contains(
                    new User(id, "Ana Ruiz", Email.of("ana.it@market-agri.test"), new PasswordHash(HASH), Role.PRODUCER));
        });
    }

    @Test
    void neitherAnUnknownNorADeletedUserIsFound() {
        rolledBack(() -> {
            insertUser("borrada.it@market-agri.test", Instant.parse("2026-11-01T00:00:00Z"));

            assertThat(accounts.findActiveByEmail(Email.of("borrada.it@market-agri.test"))).isEmpty();
            assertThat(accounts.findActiveByEmail(Email.of("nadie.it@market-agri.test"))).isEmpty();
        });
    }

    @Test
    void findsAnActiveUserByItsIdButNotADeletedOne() {
        // E-08: a deleted account is not found, as in the login.
        rolledBack(() -> {
            UUID active = insertUser("activa.id.it@market-agri.test", null);
            UUID deleted = insertUser("borrada.id.it@market-agri.test", Instant.parse("2026-11-01T00:00:00Z"));

            assertThat(profiles.findActiveById(active)).contains(new User(active, "Ana Ruiz",
                    Email.of("activa.id.it@market-agri.test"), new PasswordHash(HASH), Role.PRODUCER));
            assertThat(profiles.findActiveById(deleted)).isEmpty();
            assertThat(profiles.findActiveById(UUID.randomUUID())).isEmpty();
        });
    }

    @Test
    void aRefreshTokenIsStoredOnlyAsItsHash() {
        rolledBack(() -> {
            UUID id = insertUser("token.it@market-agri.test", null);
            Instant issuedAt = Instant.parse("2026-11-05T15:00:00Z");
            Instant expiresAt = issuedAt.plusSeconds(7 * 24 * 3600);

            String token = refreshTokens.issue(id, issuedAt, expiresAt);

            Map<String, Object> row = jdbc.sql("SELECT user_id, token_hash, expires_at, created_at, used_at, revoked_at"
                    + " FROM refresh_token WHERE user_id = :id").param("id", id).query().singleRow();
            assertThat(row.get("token_hash")).isEqualTo(OpaqueTokens.sha256Hex(token)).isNotEqualTo(token);
            assertThat(((java.sql.Timestamp) row.get("expires_at")).toInstant()).isEqualTo(expiresAt);
            assertThat(((java.sql.Timestamp) row.get("created_at")).toInstant()).isEqualTo(issuedAt);
            assertThat(row.get("used_at")).isNull();
            assertThat(row.get("revoked_at")).isNull();
            assertThat(refreshTokens.issue(id, issuedAt, expiresAt)).isNotEqualTo(token);
        });
    }
}
