package co.edu.corhuila.marketagri.auth.domain.model;

import java.util.Objects;
import java.util.UUID;

/**
 * A user of the platform (06-data/models.md, {@code user_account}). Immutable: the role is set once
 * and no operation changes it (INV-001, FR-003); only the password hash is kept (INV-003).
 */
public record User(UUID id, String name, Email email, PasswordHash passwordHash, Role role) {

    private static final int MAX_NAME_LENGTH = 150;

    public User {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(email, "email");
        Objects.requireNonNull(passwordHash, "passwordHash");
        Objects.requireNonNull(role, "role");
        if (name == null || name.isBlank() || name.strip().length() > MAX_NAME_LENGTH) {
            throw new InvalidUserException("name must have 1 to 150 characters");
        }
        name = name.strip();
    }
}
