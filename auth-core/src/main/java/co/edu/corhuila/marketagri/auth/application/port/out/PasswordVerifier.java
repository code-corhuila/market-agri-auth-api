package co.edu.corhuila.marketagri.auth.application.port.out;

import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;

/** Checks a typed password against its stored hash (bcrypt in the adapter, INV-003). */
public interface PasswordVerifier {

    boolean matches(String rawPassword, PasswordHash hash);

    /**
     * Costs the same as {@link #matches} and checks nothing: called when the email is unknown, so the
     * time of the answer does not tell whether the account exists (FR-002).
     */
    void verifyNothing(String rawPassword);
}
