package co.edu.corhuila.marketagri.auth.domain.model;

/** E-01 row 2: ADMIN is never self-registered (FR-008); only PRODUCER or BUYER. */
public class RoleNotAllowedException extends DomainException {

    public RoleNotAllowedException() {
        super("ROLE_NOT_ALLOWED", "only PRODUCER or BUYER can register");
    }
}
