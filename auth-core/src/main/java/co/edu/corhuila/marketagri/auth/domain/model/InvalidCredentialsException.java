package co.edu.corhuila.marketagri.auth.domain.model;

/**
 * E-02 rows 3 and 5: the same failure for an unknown email and a wrong password, so the answer
 * never tells whether an account exists (FR-002).
 */
public class InvalidCredentialsException extends DomainException {

    public InvalidCredentialsException() {
        super("INVALID_CREDENTIALS", "invalid credentials");
    }
}
