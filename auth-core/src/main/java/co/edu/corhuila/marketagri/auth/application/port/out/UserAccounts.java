package co.edu.corhuila.marketagri.auth.application.port.out;

import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.Optional;

/** Reads the users of auth-db. A deleted account is not found. */
public interface UserAccounts {

    Optional<User> findActiveByEmail(Email email);
}
