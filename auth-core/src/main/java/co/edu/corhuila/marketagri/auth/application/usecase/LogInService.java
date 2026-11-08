package co.edu.corhuila.marketagri.auth.application.usecase;

import co.edu.corhuila.marketagri.auth.application.port.in.LogIn;
import co.edu.corhuila.marketagri.auth.application.port.out.AccessTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.LoginAttempts;
import co.edu.corhuila.marketagri.auth.application.port.out.PasswordVerifier;
import co.edu.corhuila.marketagri.auth.application.port.out.RefreshTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import co.edu.corhuila.marketagri.auth.domain.model.AccountLockedException;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.InvalidCredentialsException;
import co.edu.corhuila.marketagri.auth.domain.model.InvalidUserException;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

/**
 * E-02 (HU-AUTH-002): the right password gives an access token of 60 minutes and a refresh token
 * of 7 days (D-C2, D-C3); every failure is the same {@code INVALID_CREDENTIALS} (FR-002). 5 wrong
 * passwords in a row lock the account for 15 minutes ({@code ACCOUNT_LOCKED}, FR-009, E-02 row 4).
 */
public class LogInService implements LogIn {

    static final Duration ACCESS_TOKEN_LIFETIME = Duration.ofMinutes(60);
    static final Duration REFRESH_TOKEN_LIFETIME = Duration.ofDays(7);
    static final int MAX_CONSECUTIVE_FAILURES = 5;
    static final Duration LOCK_DURATION = Duration.ofMinutes(15);

    private final UserAccounts accounts;
    private final PasswordVerifier passwords;
    private final AccessTokens accessTokens;
    private final RefreshTokens refreshTokens;
    private final LoginAttempts attempts;
    private final Clock clock;

    public LogInService(UserAccounts accounts, PasswordVerifier passwords, AccessTokens accessTokens,
                        RefreshTokens refreshTokens, LoginAttempts attempts, Clock clock) {
        this.accounts = accounts;
        this.passwords = passwords;
        this.accessTokens = accessTokens;
        this.refreshTokens = refreshTokens;
        this.attempts = attempts;
        this.clock = clock;
    }

    @Override
    public Session logIn(Command command) {
        Optional<User> found = findUser(command.email());
        if (found.isEmpty()) {
            passwords.verifyNothing(command.password());  // same cost as a real check (FR-002)
            throw new InvalidCredentialsException();
        }
        User user = found.get();
        // Whole seconds: iat and exp of a JWT are seconds, so expiresAt says exactly what the token says.
        Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        if (attempts.isLocked(user.id(), now)) {
            throw new AccountLockedException();  // row 4: before the password, so even the right one waits
        }
        if (!passwords.matches(command.password(), user.passwordHash())) {
            attempts.recordFailure(user.id(), now, MAX_CONSECUTIVE_FAILURES, LOCK_DURATION);
            throw new InvalidCredentialsException();  // row 5: the failure that locks still answers 401
        }
        attempts.recordSuccess(user.id());
        Instant expiresAt = now.plus(ACCESS_TOKEN_LIFETIME);
        String accessToken = accessTokens.sign(user, now, expiresAt);
        String refreshToken = refreshTokens.issue(user.id(), now, now.plus(REFRESH_TOKEN_LIFETIME));
        return new Session(accessToken, expiresAt, refreshToken, user);
    }

    /** The active user of that email; a value that cannot be an email is simply nobody. */
    private Optional<User> findUser(String rawEmail) {
        try {
            return accounts.findActiveByEmail(Email.of(rawEmail));
        } catch (InvalidUserException notAnEmail) {
            return Optional.empty();
        }
    }
}
