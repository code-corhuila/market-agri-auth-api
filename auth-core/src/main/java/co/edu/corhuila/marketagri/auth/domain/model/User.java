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

    /** Factory of a self-registered user (E-01): only a producer or a buyer (FR-008). */
    public static User register(UUID id, String name, Email email, PasswordHash passwordHash, Role role) {
        if (role != Role.PRODUCER && role != Role.BUYER) {
            throw new RoleNotAllowedException();
        }
        return new User(id, name, email, passwordHash, role);
    }

    /** Factory of the initial ADMIN (FR-008): only through a path the team operates, never E-01. */
    public static User provisionAdmin(UUID id, String name, Email email, PasswordHash passwordHash) {
        return new User(id, name, email, passwordHash, Role.ADMIN);
    }

    /**
     * E-08: a user is visible to themselves and to ADMIN only. Checked before looking the user up,
     * so the answer never tells whether an id exists.
     */
    public static void ensureVisibleTo(UUID userId, UUID callerId, Role callerRole) {
        if (!userId.equals(callerId) && callerRole != Role.ADMIN) {
            throw new UserNotVisibleException();
        }
    }
}
