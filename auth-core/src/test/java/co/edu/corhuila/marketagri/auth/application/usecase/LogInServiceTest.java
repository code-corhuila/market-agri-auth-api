package co.edu.corhuila.marketagri.auth.application.usecase;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.application.port.in.LogIn.Command;
import co.edu.corhuila.marketagri.auth.application.port.in.LogIn.Session;
import co.edu.corhuila.marketagri.auth.application.port.out.AccessTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.PasswordVerifier;
import co.edu.corhuila.marketagri.auth.application.port.out.RefreshTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import co.edu.corhuila.marketagri.auth.domain.model.DomainException;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.InvalidCredentialsException;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** E-02 in the core (HU-AUTH-002, D-C2, D-C3): a session for the right password, one answer for every failure. */
class LogInServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-05T15:00:00Z");
    private static final UUID ANA = UUID.fromString("0b6f2c7e-4a51-4c1e-9d0e-2f1c3a7b9e10");
    private static final String PASSWORD = "Productor123";
    private static final PasswordHash HASH = new PasswordHash("hash-of-" + PASSWORD);
    private static final User ANA_RUIZ =
            new User(ANA, "Ana Ruiz", Email.of("productor@market-agri.test"), HASH, Role.PRODUCER);

    /** The users of auth-db, looked up by the normalized email. */
    private static final class FakeAccounts implements UserAccounts {
        final List<Email> lookedUp = new ArrayList<>();

        @Override
        public Optional<User> findActiveByEmail(Email email) {
            lookedUp.add(email);
            return email.equals(ANA_RUIZ.email()) ? Optional.of(ANA_RUIZ) : Optional.empty();
        }
    }

    /** Matches "hash-of-<password>"; counts the dummy checks of an unknown email. */
    private static final class FakePasswords implements PasswordVerifier {
        int checks;
        int dummyChecks;

        @Override
        public boolean matches(String rawPassword, PasswordHash hash) {
            checks++;
            return hash.value().equals("hash-of-" + rawPassword);
        }

        @Override
        public void verifyNothing(String rawPassword) {
            dummyChecks++;
        }
    }

    private static final class FakeAccessTokens implements AccessTokens {
        final List<String> signed = new ArrayList<>();

        @Override
        public String sign(User user, Instant issuedAt, Instant expiresAt) {
            String token = "access:" + user.id() + ":" + user.role() + ":" + issuedAt + ":" + expiresAt;
            signed.add(token);
            return token;
        }
    }

    private static final class FakeRefreshTokens implements RefreshTokens {
        final List<String> issued = new ArrayList<>();

        @Override
        public String issue(UUID userId, Instant issuedAt, Instant expiresAt) {
            String token = "refresh:" + userId + ":" + issuedAt + ":" + expiresAt;
            issued.add(token);
            return token;
        }
    }

    private final FakeAccounts accounts = new FakeAccounts();
    private final FakePasswords passwords = new FakePasswords();
    private final FakeAccessTokens accessTokens = new FakeAccessTokens();
    private final FakeRefreshTokens refreshTokens = new FakeRefreshTokens();
    private final LogInService service = new LogInService(accounts, passwords, accessTokens, refreshTokens,
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void theRightPasswordGivesASessionForThatUser() {
        Session session = service.logIn(new Command("productor@market-agri.test", PASSWORD));

        assertThat(session.user()).isEqualTo(ANA_RUIZ);
        assertThat(session.accessToken()).isEqualTo(accessTokens.signed.get(0));
        assertThat(session.refreshToken()).isEqualTo(refreshTokens.issued.get(0));
    }

    @Test
    void theAccessTokenLasts60MinutesAndTheRefreshToken7Days() {
        Session session = service.logIn(new Command("productor@market-agri.test", PASSWORD));

        Instant accessExpiry = NOW.plus(Duration.ofMinutes(60));
        assertThat(session.expiresAt()).isEqualTo(accessExpiry);
        assertThat(accessTokens.signed).containsExactly("access:" + ANA + ":PRODUCER:" + NOW + ":" + accessExpiry);
        assertThat(refreshTokens.issued).containsExactly("refresh:" + ANA + ":" + NOW + ":" + NOW.plus(Duration.ofDays(7)));
    }

    @Test
    void theTimesAreWholeSecondsLikeTheClaimsOfTheToken() {
        // iat and exp of a JWT are seconds: expiresAt must say exactly what the token says.
        LogInService atAFraction = new LogInService(accounts, passwords, accessTokens, refreshTokens,
                Clock.fixed(NOW.plusMillis(750), ZoneOffset.UTC));

        Session session = atAFraction.logIn(new Command("productor@market-agri.test", PASSWORD));

        assertThat(session.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(60)));
    }

    @Test
    void theEmailIsLookedUpTrimmedAndLowerCased() {
        Session session = service.logIn(new Command("  Productor@Market-Agri.TEST ", PASSWORD));

        assertThat(accounts.lookedUp).containsExactly(Email.of("productor@market-agri.test"));
        assertThat(session.user()).isEqualTo(ANA_RUIZ);
    }

    @Test
    void aWrongPasswordIsInvalidCredentialsAndIssuesNothing() {
        assertThatThrownBy(() -> service.logIn(new Command("productor@market-agri.test", "Otra123")))
                .isInstanceOf(InvalidCredentialsException.class);

        assertThat(accessTokens.signed).isEmpty();
        assertThat(refreshTokens.issued).isEmpty();
    }

    @Test
    void anUnknownEmailGivesTheSameAnswerAndCostsAPasswordCheck() {
        // FR-002: unknown email and wrong password are indistinguishable from outside, also in time.
        Throwable unknown = catchFailure(new Command("nadie@market-agri.test", PASSWORD));
        Throwable wrong = catchFailure(new Command("productor@market-agri.test", "Otra123"));

        assertThat(unknown).isInstanceOf(InvalidCredentialsException.class);
        assertThat(unknown.getClass()).isEqualTo(wrong.getClass());
        assertThat(unknown.getMessage()).isEqualTo(wrong.getMessage());
        assertThat(((DomainException) unknown).code()).isEqualTo("INVALID_CREDENTIALS");
        assertThat(passwords.dummyChecks).isEqualTo(1);
        assertThat(accessTokens.signed).isEmpty();
        assertThat(refreshTokens.issued).isEmpty();
    }

    @Test
    void anEmailThatCannotExistIsAlsoInvalidCredentials() {
        // The card's 400 is only for a missing or empty field; any other value is just not a user.
        assertThatThrownBy(() -> service.logIn(new Command("no-es-un-correo", PASSWORD)))
                .isInstanceOf(InvalidCredentialsException.class);
        assertThat(accounts.lookedUp).isEmpty();
        assertThat(passwords.dummyChecks).isEqualTo(1);
    }

    @Test
    void theCommandNeverPrintsThePassword() {
        // NFR-052: a log line or an exception that prints the command never carries the password.
        assertThat(new Command("productor@market-agri.test", PASSWORD).toString()).doesNotContain(PASSWORD);
    }

    private Throwable catchFailure(Command command) {
        try {
            service.logIn(command);
        } catch (RuntimeException failure) {
            return failure;
        }
        throw new AssertionError("expected a failure for " + command.email());
    }
}
