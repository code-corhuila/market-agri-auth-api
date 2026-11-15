package co.edu.corhuila.marketagri.auth.application.port.out;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/** The lockout state of an account (HU-AUTH-005): consecutive failed logins and the end of a lock. */
public interface LoginAttempts {

    boolean isLocked(UUID userId, Instant now);

    /** Counts a failure; the {@code maxFailures}-th in a row locks until {@code now + lock}. Atomic. */
    void recordFailure(UUID userId, Instant now, int maxFailures, Duration lock);

    /** A successful login: no failures, no lock. */
    void recordSuccess(UUID userId);
}
