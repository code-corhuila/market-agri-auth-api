package co.edu.corhuila.marketagri.auth.domain.model;

/**
 * The stored hash of a password (INV-003). The core never sees how it was made: only the
 * {@code PasswordVerifier} adapter does. Never printed (NFR-032).
 */
public record PasswordHash(String value) {

    public PasswordHash {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("empty password hash");
        }
    }

    @Override
    public String toString() {
        return "PasswordHash[***]";
    }
}
