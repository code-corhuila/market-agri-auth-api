package co.edu.corhuila.marketagri.auth.domain.model;

/** E-08 row 2: only the user themselves or ADMIN may see a user; {@code 403 FORBIDDEN}. */
public class UserNotVisibleException extends DomainException {

    public UserNotVisibleException() {
        super("FORBIDDEN", "caller may not see this user");
    }
}
