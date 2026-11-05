package co.edu.corhuila.marketagri.auth.domain.model;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The login credential (INV-002). Always trimmed and lower-cased, so the same address is one value:
 * the unique index of auth-db compares what this class produced.
 */
public record Email(String value) {

    private static final int MAX_LENGTH = 255;
    /** Something before and after one {@code @}, a dot in the domain, no spaces: format, not deliverability. */
    private static final Pattern FORMAT = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    public Email {
        if (value == null || !FORMAT.matcher(value).matches() || value.length() > MAX_LENGTH
                || !value.equals(value.strip().toLowerCase(Locale.ROOT))) {
            throw new InvalidUserException("invalid email");
        }
    }

    /** What a person typed, normalized. */
    public static Email of(String raw) {
        if (raw == null) {
            throw new InvalidUserException("missing email");
        }
        return new Email(raw.strip().toLowerCase(Locale.ROOT));
    }
}
