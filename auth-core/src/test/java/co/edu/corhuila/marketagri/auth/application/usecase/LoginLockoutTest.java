package co.edu.corhuila.marketagri.auth.application.usecase;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.application.port.in.LogIn.Command;
import co.edu.corhuila.marketagri.auth.application.port.out.LoginAttempts;
import co.edu.corhuila.marketagri.auth.application.port.out.PasswordVerifier;
import co.edu.corhuila.marketagri.auth.domain.model.AccountLockedException;
import co.edu.corhuila.marketagri.auth.domain.model.DomainException;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.InvalidCredentialsException;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * HU-AUTH-005 in the core (FR-009, E-02 rows 4 and 5): 5 consecutive wrong passwords lock the
 * account for 15 minutes; the 5th still answers 401; a locked account answers 423 even with the
 * right password; a successful login resets the count; an unknown email is never 423 (FR-002).
 */
class LoginLockoutTest {

    private static final String EMAIL = "productor@market-agri.test";
    private static final String PASSWORD = "Productor123";
    private static final User ANA = new User(UUID.fromString("0b6f2c7e-4a51-4c1e-9d0e-2f1c3a7b9e10"), "Ana Ruiz",
            Email.of(EMAIL), new PasswordHash("hash-of-" + PASSWORD), Role.PRODUCER);

    /** A clock the test moves forward. */
    private static final class MovingClock extends Clock {
        Instant now = Instant.parse("2026-11-07T15:00:00Z");

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** user_account's lockout state in memory, with the rule the atomic UPDATE applies. */
    private static final class FakeAttempts implements LoginAttempts {
        int failures;
        Instant lockedUntil;
        final List<String> calls = new ArrayList<>();

        @Override
        public boolean isLocked(UUID userId, Instant now) {
            return lockedUntil != null && lockedUntil.isAfter(now);
        }

        @Override
        public void recordFailure(UUID userId, Instant now, int maxFailures, Duration lock) {
            calls.add("failure");
            failures++;
            if (failures >= maxFailures) {
                failures = 0;
                lockedUntil = now.plus(lock);
            }
        }

        @Override
        public void recordSuccess(UUID userId) {
            calls.add("success");
            failures = 0;
            lockedUntil = null;
        }
    }

    private static final PasswordVerifier PASSWORDS = new PasswordVerifier() {
        @Override
        public boolean matches(String rawPassword, PasswordHash hash) {
            return hash.value().equals("hash-of-" + rawPassword);
        }

        @Override
        public void verifyNothing(String rawPassword) {
        }
    };

    private final MovingClock clock = new MovingClock();
    private final FakeAttempts attempts = new FakeAttempts();
    private final LogInService service = new LogInService(
            email -> email.equals(ANA.email()) ? Optional.of(ANA) : Optional.empty(), PASSWORDS,
            (user, issuedAt, expiresAt) -> "access", (userId, issuedAt, expiresAt) -> "refresh", attempts, clock);

    private void wrongPassword(int times) {
        for (int i = 0; i < times; i++) {
            assertThatThrownBy(() -> service.logIn(new Command(EMAIL, "Otra123")))
                    .isInstanceOf(InvalidCredentialsException.class);
        }
    }

    @Test
    void fourWrongPasswordsThenTheRightOneLogsInAndResetsTheCount() {
        wrongPassword(4);

        assertThat(service.logIn(new Command(EMAIL, PASSWORD)).user()).isEqualTo(ANA);
        assertThat(attempts.failures).isEqualTo(0);
        assertThat(attempts.calls).containsExactly("failure", "failure", "failure", "failure", "success");
    }

    @Test
    void theFifthWrongPasswordStillAnswers401AndTheNextEvenRightOneAnswers423() {
        wrongPassword(5);

        assertThatThrownBy(() -> service.logIn(new Command(EMAIL, PASSWORD)))
                .isInstanceOf(AccountLockedException.class);
        assertThat(((DomainException) failureOf(new Command(EMAIL, "Otra123"))).code()).isEqualTo("ACCOUNT_LOCKED");
        assertThat(attempts.calls).hasSize(5);  // a locked attempt neither counts nor resets
    }

    @Test
    void after15MinutesTheRightPasswordLogsInAgain() {
        wrongPassword(5);
        clock.now = clock.now.plus(Duration.ofMinutes(14)).plusSeconds(59);
        assertThatThrownBy(() -> service.logIn(new Command(EMAIL, PASSWORD))).isInstanceOf(AccountLockedException.class);

        clock.now = clock.now.plusSeconds(1);

        assertThat(service.logIn(new Command(EMAIL, PASSWORD)).user()).isEqualTo(ANA);
    }

    @Test
    void anUnknownEmailIsAlways401NeverLocked() {
        for (int i = 0; i < 7; i++) {
            assertThat(((DomainException) failureOf(new Command("nadie@market-agri.test", "Otra123"))).code())
                    .isEqualTo("INVALID_CREDENTIALS");
        }
        assertThat(attempts.calls).isEmpty();
    }

    private Throwable failureOf(Command command) {
        try {
            service.logIn(command);
            throw new AssertionError("expected a failure");
        } catch (DomainException failure) {
            return failure;
        }
    }
}
