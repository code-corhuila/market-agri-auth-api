package co.edu.corhuila.marketagri.auth.domain.model;

/** E-08 row 3: no such user, reachable only by ADMIN (the others are 403 first). */
public class UserNotFoundException extends DomainException {

    public UserNotFoundException() {
        super("USER_NOT_FOUND", "user not found");
    }
}
