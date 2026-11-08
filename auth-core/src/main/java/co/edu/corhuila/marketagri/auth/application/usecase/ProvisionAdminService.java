package co.edu.corhuila.marketagri.auth.application.usecase;

import co.edu.corhuila.marketagri.auth.application.port.in.ProvisionAdmin;
import co.edu.corhuila.marketagri.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import co.edu.corhuila.marketagri.auth.application.port.out.UserRegistrations;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.Optional;
import java.util.UUID;

/**
 * FR-008: creates the initial ADMIN once; a later start that finds it changes nothing (the password
 * of an existing ADMIN is not reset). An email held by another role stops the start: a role never
 * changes (INV-001), and an environment without its ADMIN must not look healthy.
 */
public final class ProvisionAdminService implements ProvisionAdmin {

    static final String ADMIN_NAME = "Administración";
    private static final int PASSWORD_MIN = 8;
    private static final int PASSWORD_MAX = 100;

    private final UserAccounts accounts;
    private final UserRegistrations registrations;
    private final PasswordHasher passwords;

    public ProvisionAdminService(UserAccounts accounts, UserRegistrations registrations, PasswordHasher passwords) {
        this.accounts = accounts;
        this.registrations = registrations;
        this.passwords = passwords;
    }

    @Override
    public Outcome provision(Command command) {
        Email email = Email.of(command.email());
        Optional<User> existing = accounts.findActiveByEmail(email);
        if (existing.isPresent()) {
            if (existing.get().role() != Role.ADMIN) {
                throw new IllegalStateException("AUTH_ADMIN_EMAIL belongs to a user that is not ADMIN");
            }
            return Outcome.ALREADY_PRESENT;
        }
        String password = command.password();
        if (password == null || password.length() < PASSWORD_MIN || password.length() > PASSWORD_MAX) {
            throw new IllegalArgumentException("AUTH_ADMIN_PASSWORD must have 8 to 100 characters");
        }
        registrations.add(User.provisionAdmin(UUID.randomUUID(), ADMIN_NAME, email, passwords.hash(password)));
        return Outcome.CREATED;
    }
}
