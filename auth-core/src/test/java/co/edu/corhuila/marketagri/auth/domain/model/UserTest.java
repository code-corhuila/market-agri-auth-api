package co.edu.corhuila.marketagri.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** A user of the platform: one immutable role (INV-001) and only a password hash (INV-003). */
class UserTest {

    private static final UUID ID = UUID.fromString("0b6f2c7e-4a51-4c1e-9d0e-2f1c3a7b9e10");
    private static final PasswordHash HASH = new PasswordHash("$2a$12$hash-from-the-database");

    @Test
    void keepsItsDataWithTheNameTrimmed() {
        User user = new User(ID, "  Ana Ruiz ", Email.of("productor@market-agri.test"), HASH, Role.PRODUCER);

        assertThat(user.id()).isEqualTo(ID);
        assertThat(user.name()).isEqualTo("Ana Ruiz");
        assertThat(user.email()).isEqualTo(Email.of("productor@market-agri.test"));
        assertThat(user.passwordHash()).isEqualTo(HASH);
        assertThat(user.role()).isEqualTo(Role.PRODUCER);
    }

    @Test
    void theNameHasOneTo150Characters() {
        assertThat(new User(ID, "n".repeat(150), Email.of("a@b.co"), HASH, Role.BUYER).name()).hasSize(150);
        assertThatThrownBy(() -> new User(ID, "   ", Email.of("a@b.co"), HASH, Role.BUYER))
                .isInstanceOf(InvalidUserException.class);
        assertThatThrownBy(() -> new User(ID, "n".repeat(151), Email.of("a@b.co"), HASH, Role.BUYER))
                .isInstanceOf(InvalidUserException.class);
    }

    @Test
    void everyPartIsRequired() {
        Email email = Email.of("a@b.co");
        assertThatThrownBy(() -> new User(null, "Ana", email, HASH, Role.BUYER)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new User(ID, null, email, HASH, Role.BUYER)).isInstanceOf(InvalidUserException.class);
        assertThatThrownBy(() -> new User(ID, "Ana", null, HASH, Role.BUYER)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new User(ID, "Ana", email, null, Role.BUYER)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new User(ID, "Ana", email, HASH, null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void theRoleCanNeverChange() {
        // INV-001 / FR-003: there is no operation that changes a user; a new role would be a new value.
        boolean mutator = Arrays.stream(User.class.getMethods())
                .map(Method::getName)
                .anyMatch(name -> name.startsWith("set") || name.startsWith("with") || name.startsWith("assign")
                        || name.startsWith("change"));
        assertThat(mutator).isFalse();
    }

    @Test
    void thePasswordHashIsNeverPrinted() {
        // NFR-032: a log line or an exception that prints the user never carries the hash.
        User user = new User(ID, "Ana Ruiz", Email.of("a@b.co"), HASH, Role.PRODUCER);
        assertThat(HASH.toString()).doesNotContain("$2a$12$");
        assertThat(user.toString()).doesNotContain("$2a$12$");
    }

    @Test
    void anEmptyHashIsRefused() {
        assertThatThrownBy(() -> new PasswordHash(" ")).isInstanceOf(IllegalArgumentException.class);
    }
}
