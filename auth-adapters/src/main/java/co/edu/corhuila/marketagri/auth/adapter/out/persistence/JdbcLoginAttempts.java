package co.edu.corhuila.marketagri.auth.adapter.out.persistence;

import co.edu.corhuila.marketagri.auth.application.port.out.LoginAttempts;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * The lockout state of {@code user_account} (HU-AUTH-005), as auth_app. Counting and locking are
 * one UPDATE: the row lock it takes makes two failures at the same time count as two, so the 5th
 * can never be skipped.
 */
public final class JdbcLoginAttempts implements LoginAttempts {

    private final JdbcClient jdbc;

    public JdbcLoginAttempts(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public boolean isLocked(UUID userId, Instant now) {
        return jdbc.sql("SELECT locked_until IS NOT NULL AND locked_until > :now FROM user_account WHERE id = :id")
                .param("id", userId)
                .param("now", now.atOffset(ZoneOffset.UTC))
                .query(Boolean.class)
                .optional()
                .orElse(false);
    }

    @Override
    public void recordFailure(UUID userId, Instant now, int maxFailures, Duration lock) {
        jdbc.sql("""
                        UPDATE user_account
                        SET locked_until = CASE WHEN failed_login_count + 1 >= :max THEN :lockedUntil ELSE locked_until END,
                            failed_login_count = CASE WHEN failed_login_count + 1 >= :max THEN 0 ELSE failed_login_count + 1 END
                        WHERE id = :id""")
                .param("id", userId)
                .param("max", maxFailures)
                .param("lockedUntil", now.plus(lock).atOffset(ZoneOffset.UTC))
                .update();
    }

    @Override
    public void recordSuccess(UUID userId) {
        jdbc.sql("""
                        UPDATE user_account SET failed_login_count = 0, locked_until = NULL
                        WHERE id = :id AND (failed_login_count <> 0 OR locked_until IS NOT NULL)""")
                .param("id", userId)
                .update();
    }
}
