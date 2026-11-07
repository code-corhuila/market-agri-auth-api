package co.edu.corhuila.marketagri.auth.application.usecase;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.application.port.in.Register.Command;
import co.edu.corhuila.marketagri.auth.application.port.in.Register.Registration;
import co.edu.corhuila.marketagri.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.marketagri.auth.application.port.out.UnitOfWork;
import co.edu.corhuila.marketagri.auth.application.port.out.UserRegistrations;
import co.edu.corhuila.marketagri.auth.domain.model.DomainException;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.EmailAlreadyRegisteredException;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.RoleNotAllowedException;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * E-01 in the core (HU-AUTH-001, D-C35): checks in the order of the card — 400, 422, the replay of a
 * used key, then 409 — and the user and its key in one transaction.
 */
class RegisterServiceTest {

    private static final String KEY = "registro-ana-0001";
    private static final String PASSWORD = "Productor123";
    private static final PasswordHasher HASHER = raw -> new PasswordHash("hash-of-" + raw);

    /** auth-db in memory: a transaction that fails leaves nothing behind. */
    private static final class FakeStore implements UserRegistrations, UnitOfWork {
        final Map<String, User> byEmail = new HashMap<>();
        final Map<String, UUID> keys = new HashMap<>();
        /** A concurrent request of the same intent that commits while this one runs. */
        Runnable concurrentCommit = () -> { };

        @Override
        public <T> T inTransaction(Supplier<T> work) {
            concurrentCommit.run();
            Map<String, User> users = new HashMap<>(byEmail);
            Map<String, UUID> claimed = new HashMap<>(keys);
            try {
                return work.get();
            } catch (RuntimeException failure) {
                byEmail.clear();
                byEmail.putAll(users);
                keys.clear();
                keys.putAll(claimed);
                throw failure;
            }
        }

        @Override
        public void add(User user) {
            if (byEmail.containsKey(user.email().value())) {
                throw new EmailAlreadyRegisteredException();
            }
            byEmail.put(user.email().value(), user);
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

        User commit(String name, String email, String key) {
            User user = new User(UUID.randomUUID(), name, Email.of(email), new PasswordHash("x"), Role.BUYER);
            byEmail.put(user.email().value(), user);
            keys.put(key, user.id());
            return user;
        }
    }

    private final FakeStore store = new FakeStore();
    private final RegisterService service = new RegisterService(store, HASHER, store);

    private static Command command(String email, Role role, String key) {
        return new Command("  Ana Ruiz ", email, PASSWORD, role, key);
    }

    @Test
    void aProducerIsCreatedWithTheHashTheNormalizedEmailAndItsKey() {
        Registration registration = service.register(command(" Ana@Finca.CO ", Role.PRODUCER, KEY));

        User user = registration.user();
        assertThat(registration.created()).isTrue();
        assertThat(user.name()).isEqualTo("Ana Ruiz");
        assertThat(user.email()).isEqualTo(Email.of("ana@finca.co"));
        assertThat(user.role()).isEqualTo(Role.PRODUCER);
        assertThat(user.passwordHash()).isEqualTo(new PasswordHash("hash-of-" + PASSWORD));
        assertThat(store.userForKey(KEY)).contains(user);
    }

    @Test
    void adminIs422BeforeTheReplayOfAUsedKeyAndNothingIsStored() {
        store.commit("Otro", "otro@finca.co", KEY);

        assertThatThrownBy(() -> service.register(command("admin@finca.co", Role.ADMIN, KEY)))
                .isInstanceOf(RoleNotAllowedException.class);
        assertThat(((DomainException) failureOf(command("admin@finca.co", Role.ADMIN, "otra-llave-01"))).code())
                .isEqualTo("ROLE_NOT_ALLOWED");
        assertThat(store.byEmail).hasSize(1);
    }

    @Test
    void aUsedKeyAnswersTheOriginalUserAndCreatesNothingEvenIfItsEmailExists() {
        User original = store.commit("Ana Ruiz", "ana@finca.co", KEY);

        Registration replay = service.register(command("ana@finca.co", Role.PRODUCER, KEY));

        assertThat(replay.created()).isFalse();
        assertThat(replay.user()).isEqualTo(original);
        assertThat(store.byEmail).hasSize(1);
    }

    @Test
    void anEmailAlreadyRegisteredInAnyCaseIs409AndItsKeyIsNotKept() {
        store.commit("Ana Ruiz", "ana@finca.co", "otra-llave-01");

        assertThatThrownBy(() -> service.register(command("ANA@finca.co", Role.BUYER, KEY)))
                .isInstanceOf(EmailAlreadyRegisteredException.class);
        assertThat(((DomainException) failureOf(command("ana@finca.co", Role.BUYER, KEY))).code())
                .isEqualTo("EMAIL_ALREADY_REGISTERED");
        assertThat(store.keys).doesNotContainKey(KEY);
    }

    @Test
    void aRetryThatLosesTheRaceToItsOwnFirstRequestAnswersTheOriginalNever409() {
        List<User> committed = new ArrayList<>();
        store.concurrentCommit = () -> {
            if (committed.isEmpty()) {
                committed.add(store.commit("Ana Ruiz", "ana@finca.co", KEY));
            }
        };

        Registration replay = service.register(command("ana@finca.co", Role.PRODUCER, KEY));

        assertThat(replay.created()).isFalse();
        assertThat(replay.user()).isEqualTo(committed.get(0));
        assertThat(store.byEmail).hasSize(1);
    }

    @Test
    void theCommandNeverPrintsThePassword() {
        assertThat(command("ana@finca.co", Role.BUYER, KEY).toString()).doesNotContain(PASSWORD);
    }

    private Throwable failureOf(Command command) {
        try {
            service.register(command);
            throw new AssertionError("expected a failure");
        } catch (DomainException failure) {
            return failure;
        }
    }
}
