package co.edu.corhuila.marketagri.auth.application.port.out;

import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.Optional;
import java.util.UUID;

/** Where a new user and its {@code Idempotency-Key} are stored, in one {@link UnitOfWork} (D-C35). */
public interface UserRegistrations {

    /** {@code EmailAlreadyRegisteredException} when the normalized email exists. */
    void add(User user);

    /** False when the key was already used: nothing is written. */
    boolean claimKey(String idempotencyKey, UUID userId);

    /** The user created earlier with this key, if any. */
    Optional<User> userForKey(String idempotencyKey);
}
