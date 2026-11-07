package co.edu.corhuila.marketagri.auth.adapter.out.persistence;

import co.edu.corhuila.marketagri.auth.application.port.out.UserRegistrations;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.EmailAlreadyRegisteredException;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.Optional;
import java.util.UUID;
import org.postgresql.util.PSQLException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * {@code user_account} and {@code idempotency_key} of auth-db for E-01, as auth_app (D-C35). The
 * unique index on the email decides between two registrations at once: the loser gets 409.
 */
public final class JdbcUserRegistrations implements UserRegistrations {

    private static final String UNIQUE_EMAIL = "uq_user_account_email";

    private final JdbcClient jdbc;

    public JdbcUserRegistrations(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void add(User user) {
        try {
            jdbc.sql("""
                            INSERT INTO user_account (id, name, email, password_hash, role)
                            VALUES (:id, :name, :email, :passwordHash, :role)""")
                    .param("id", user.id())
                    .param("name", user.name())
                    .param("email", user.email().value())
                    .param("passwordHash", user.passwordHash().value())
                    .param("role", user.role().name())
                    .update();
        } catch (DuplicateKeyException violation) {
            if (violation.getCause() instanceof PSQLException cause && cause.getServerErrorMessage() != null
                    && UNIQUE_EMAIL.equals(cause.getServerErrorMessage().getConstraint())) {
                throw new EmailAlreadyRegisteredException();
            }
            throw violation;
        }
    }

    @Override
    public boolean claimKey(String idempotencyKey, UUID userId) {
        // A concurrent claim of the same key waits for the first transaction, then inserts nothing.
        return jdbc.sql("""
                        INSERT INTO idempotency_key (key_value, user_id)
                        VALUES (:keyValue, :userId)
                        ON CONFLICT (key_value) DO NOTHING""")
                .param("keyValue", idempotencyKey)
                .param("userId", userId)
                .update() == 1;
    }

    @Override
    public Optional<User> userForKey(String idempotencyKey) {
        return jdbc.sql("""
                        SELECT u.id, u.name, u.email, u.password_hash, u.role
                        FROM idempotency_key k JOIN user_account u ON u.id = k.user_id
                        WHERE k.key_value = :keyValue""")
                .param("keyValue", idempotencyKey)
                .query((row, number) -> new User(
                        row.getObject("id", UUID.class),
                        row.getString("name"),
                        new Email(row.getString("email")),
                        new PasswordHash(row.getString("password_hash")),
                        Role.valueOf(row.getString("role"))))
                .optional();
    }
}
