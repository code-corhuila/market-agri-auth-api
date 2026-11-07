package co.edu.corhuila.marketagri.auth.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.application.port.out.UserRegistrations;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.EmailAlreadyRegisteredException;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The SQL of E-01 against the real tables of auth-db (D-C35): the user and its key, the unique
 * email turned into 409, and a key used once. auth_app has no DELETE: every test is rolled back.
 */
@SpringBootTest
class AuthRegistrationsIT extends AuthIntegrationTest {

    private static final PasswordHash HASH =
            new PasswordHash("$2a$12$yHcEDghcNSsOFt4XSsWEWO0AVS2aUhwG.ZAjAu4hfONWrdvM4lnSC");

    @Autowired
    private UserRegistrations registrations;

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

    private static User user(String email, Role role) {
        return new User(UUID.randomUUID(), "Ana Ruiz", Email.of(email), HASH, role);
    }

    @Test
    void aNewUserAndItsKeyAreStoredAndTheKeyFindsTheUser() {
        rolledBack(() -> {
            User ana = user("ana.registro.it@market-agri.test", Role.PRODUCER);

            registrations.add(ana);

            assertThat(registrations.claimKey("registro-it-0001", ana.id())).isTrue();
            assertThat(registrations.userForKey("registro-it-0001")).contains(ana);
            assertThat(registrations.userForKey("registro-it-otra")).isEmpty();
            assertThat(jdbc.sql("SELECT role FROM user_account WHERE id = :id").param("id", ana.id())
                    .query(String.class).single()).isEqualTo("PRODUCER");
        });
    }

    @Test
    void aKeyIsClaimedOnlyOnce() {
        rolledBack(() -> {
            User ana = user("ana.llave.it@market-agri.test", Role.BUYER);
            User otra = user("otra.llave.it@market-agri.test", Role.BUYER);
            registrations.add(ana);
            registrations.add(otra);

            assertThat(registrations.claimKey("registro-it-0002", ana.id())).isTrue();
            assertThat(registrations.claimKey("registro-it-0002", otra.id())).isFalse();
            assertThat(registrations.userForKey("registro-it-0002")).contains(ana);
        });
    }

    @Test
    void theUniqueEmailOfAuthDbIsEmailAlreadyRegistered() {
        assertThatThrownBy(() -> rolledBack(() -> {
            registrations.add(user("repetida.it@market-agri.test", Role.BUYER));
            registrations.add(user("repetida.it@market-agri.test", Role.PRODUCER));
        })).isInstanceOf(EmailAlreadyRegisteredException.class);
    }
}
