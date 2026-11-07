package co.edu.corhuila.marketagri.auth.application.port.out;

import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.Optional;
import java.util.UUID;

/** Reads a user of auth-db by id. A deleted account is not found. */
public interface UserProfiles {

    Optional<User> findActiveById(UUID id);
}
