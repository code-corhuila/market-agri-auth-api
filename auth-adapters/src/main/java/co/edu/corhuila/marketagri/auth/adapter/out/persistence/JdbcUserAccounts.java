package co.edu.corhuila.marketagri.auth.adapter.out.persistence;

import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import co.edu.corhuila.marketagri.auth.application.port.out.UserProfiles;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;

/** {@code user_account} of auth-db, as auth_app. The email is stored already normalized (INV-002). */
public final class JdbcUserAccounts implements UserAccounts, UserProfiles {

    private final JdbcClient jdbc;

    public JdbcUserAccounts(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<User> findActiveByEmail(Email email) {
        return jdbc.sql("""
                        SELECT id, name, email, password_hash, role
                        FROM user_account
                        WHERE email = :email AND deleted_at IS NULL
                        """)
                .param("email", email.value())
                .query(JdbcUserAccounts::user)
                .optional();
    }

    @Override
    public Optional<User> findActiveById(UUID id) {
        return jdbc.sql("""
                        SELECT id, name, email, password_hash, role
                        FROM user_account
                        WHERE id = :id AND deleted_at IS NULL
                        """)
                .param("id", id)
                .query(JdbcUserAccounts::user)
                .optional();
    }

    private static User user(ResultSet row, int number) throws SQLException {
        return new User(
                row.getObject("id", UUID.class),
                row.getString("name"),
                new Email(row.getString("email")),
                new PasswordHash(row.getString("password_hash")),
                Role.valueOf(row.getString("role")));
    }
}
