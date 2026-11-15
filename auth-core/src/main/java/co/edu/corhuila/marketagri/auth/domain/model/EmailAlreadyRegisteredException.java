package co.edu.corhuila.marketagri.auth.domain.model;

/** E-01 row 4: one account per normalized email (INV-002); the unique index of auth-db decides. */
public class EmailAlreadyRegisteredException extends DomainException {

    public EmailAlreadyRegisteredException() {
        super("EMAIL_ALREADY_REGISTERED", "email already registered");
    }
}
