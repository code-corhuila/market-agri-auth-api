package co.edu.corhuila.marketagri.auth.application.usecase;

import co.edu.corhuila.marketagri.auth.application.port.in.Register;
import co.edu.corhuila.marketagri.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.marketagri.auth.application.port.out.UnitOfWork;
import co.edu.corhuila.marketagri.auth.application.port.out.UserRegistrations;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.EmailAlreadyRegisteredException;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.Optional;
import java.util.UUID;

/**
 * E-01 in the order of its card: the rules of the user (400, 422), then the replay of a used key
 * (200), then the unique email (409). The user and its key go in one transaction (D-C35); a request
 * that loses the race to its own retry answers the original user, never 409.
 */
public final class RegisterService implements Register {

    private final UserRegistrations registrations;
    private final PasswordHasher passwords;
    private final UnitOfWork unitOfWork;

    public RegisterService(UserRegistrations registrations, PasswordHasher passwords, UnitOfWork unitOfWork) {
        this.registrations = registrations;
        this.passwords = passwords;
        this.unitOfWork = unitOfWork;
    }

    @Override
    public Registration register(Command command) {
        User user = User.register(UUID.randomUUID(), command.name(), Email.of(command.email()),
                passwords.hash(command.password()), command.role());
        Optional<User> original = registrations.userForKey(command.idempotencyKey());
        if (original.isPresent()) {
            return new Registration(original.get(), false);
        }
        try {
            return unitOfWork.inTransaction(() -> {
                registrations.add(user);
                if (!registrations.claimKey(command.idempotencyKey(), user.id())) {
                    throw new KeyAlreadyUsed();
                }
                return new Registration(user, true);
            });
        } catch (KeyAlreadyUsed | EmailAlreadyRegisteredException lost) {
            // Another request with the same key committed first: it is this intent, so answer it.
            return registrations.userForKey(command.idempotencyKey())
                    .map(committed -> new Registration(committed, false))
                    .orElseThrow(() -> lost);
        }
    }

    /** Only rolls the unit of work back; never leaves this class. */
    private static final class KeyAlreadyUsed extends RuntimeException {
        KeyAlreadyUsed() {
            super(null, null, false, false);
        }
    }
}
