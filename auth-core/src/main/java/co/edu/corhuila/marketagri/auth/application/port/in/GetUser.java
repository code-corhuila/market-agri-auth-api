package co.edu.corhuila.marketagri.auth.application.port.in;

import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.UUID;

/** E-08: one user, for the user themselves or ADMIN (the Location of E-01, D-C35). */
public interface GetUser {

    User get(Query query);

    /** Who asks (from the verified token) and which user. */
    record Query(UUID callerId, Role callerRole, UUID userId) {
    }
}
