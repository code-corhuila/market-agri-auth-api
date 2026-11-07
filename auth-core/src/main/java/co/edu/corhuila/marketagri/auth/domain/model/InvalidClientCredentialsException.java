package co.edu.corhuila.marketagri.auth.domain.model;

/** I-01: the same failure for an unknown client and a wrong secret (api-contract §4.1). */
public class InvalidClientCredentialsException extends DomainException {

    public InvalidClientCredentialsException() {
        super("INVALID_CLIENT_CREDENTIALS", "invalid client credentials");
    }
}
