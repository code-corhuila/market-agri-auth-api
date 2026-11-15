package co.edu.corhuila.marketagri.auth.application.usecase;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.application.port.in.ProvisionAdmin.Command;
import co.edu.corhuila.marketagri.auth.application.port.in.ProvisionAdmin.Outcome;
import co.edu.corhuila.marketagri.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import co.edu.corhuila.marketagri.auth.application.port.out.UserRegistrations;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * FR-008 in the core: the initial ADMIN comes from a path the team operates (ADR-020 point 8), never
 * from E-01. Created once; a start-up that finds it does nothing; an email held by another role stops.
 */
class ProvisionAdminServiceTest {

    private static final String PASSWORD = "Admin-de-main-2026";

    /** user_account in memory, read by email and written as E-01 writes it. */
    private static final class FakeUsers implements UserAccounts, UserRegistrations {
        final Map<String, User> byEmail = new HashMap<>();

        @Override
        public Optional<User> findActiveByEmail(Email email) {
            return Optional.ofNullable(byEmail.get(email.value()));
        }

        @Override
        public void add(User user) {
            byEmail.put(user.email().value(), user);
        }

        @Override
        public boolean claimKey(String idempotencyKey, UUID userId) {
            throw new AssertionError("the initial ADMIN has no Idempotency-Key");
        }

        @Override
        public Optional<User> userForKey(String idempotencyKey) {
            throw new AssertionError("the initial ADMIN has no Idempotency-Key");
        }
    }

    private static final PasswordHasher HASHER = raw -> new PasswordHash("hash-of-" + raw);

    private final FakeUsers users = new FakeUsers();
    private final ProvisionAdminService service = new ProvisionAdminService(users, users, HASHER);

    @Test
    void createsTheAdminWithTheNormalizedEmailAndOnlyTheHash() {
        Outcome outcome = service.provision(new Command(" Admin@Market-Agri.CO ", PASSWORD));

        User admin = users.byEmail.get("admin@market-agri.co");
        assertThat(outcome).isEqualTo(Outcome.CREATED);
        assertThat(admin.role()).isEqualTo(Role.ADMIN);
        assertThat(admin.name()).isEqualTo("Administración");
        assertThat(admin.passwordHash()).isEqualTo(new PasswordHash("hash-of-" + PASSWORD));
    }

    @Test
    void anAdminAlreadyThereIsLeftUntouched() {
        service.provision(new Command("admin@market-agri.co", PASSWORD));
        User first = users.byEmail.get("admin@market-agri.co");

        Outcome again = service.provision(new Command("admin@market-agri.co", "Otra-clave-distinta"));

        assertThat(again).isEqualTo(Outcome.ALREADY_PRESENT);
        assertThat(users.byEmail.get("admin@market-agri.co")).isEqualTo(first);
    }

    @Test
    void anEmailThatBelongsToAnotherRoleStopsTheStartWithoutChangingIt() {
        User buyer = new User(UUID.randomUUID(), "Carlos", Email.of("admin@market-agri.co"), new PasswordHash("x"), Role.BUYER);
        users.add(buyer);

        assertThatThrownBy(() -> service.provision(new Command("admin@market-agri.co", PASSWORD)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("AUTH_ADMIN_EMAIL");
        assertThat(users.byEmail.get("admin@market-agri.co")).isEqualTo(buyer);  // INV-001: a role never changes
    }

    @Test
    void aPasswordOutsideEightToOneHundredIsRefusedAndNeverPrinted() {
        for (String password : new String[] {"Corta12", "x".repeat(101)}) {
            assertThatThrownBy(() -> service.provision(new Command("admin@market-agri.co", password)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("AUTH_ADMIN_PASSWORD")
                    .hasMessageNotContaining(password);
        }
        assertThat(users.byEmail).isEmpty();
    }

    @Test
    void theCommandNeverPrintsThePassword() {
        assertThat(new Command("admin@market-agri.co", PASSWORD).toString()).doesNotContain(PASSWORD);
    }
}
