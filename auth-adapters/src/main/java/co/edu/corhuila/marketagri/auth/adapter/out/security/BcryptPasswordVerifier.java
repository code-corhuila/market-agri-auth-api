package co.edu.corhuila.marketagri.auth.adapter.out.security;

import co.edu.corhuila.marketagri.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.marketagri.auth.application.port.out.PasswordVerifier;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import java.util.UUID;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** bcrypt of cost 12, the hashes auth-db stores (INV-003, its CHECK on the cost): checks them and makes new ones. */
public final class BcryptPasswordVerifier implements PasswordVerifier, PasswordHasher {

    private static final int COST = 12;

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(COST);
    /** A real hash of a random value, made once: comparing against it costs the same as a real check. */
    private final String unusableHash = bcrypt.encode(UUID.randomUUID().toString());

    @Override
    public boolean matches(String rawPassword, PasswordHash hash) {
        return bcrypt.matches(rawPassword, hash.value());
    }

    @Override
    public void verifyNothing(String rawPassword) {
        bcrypt.matches(rawPassword, unusableHash);
    }

    @Override
    public PasswordHash hash(String rawPassword) {
        return new PasswordHash(bcrypt.encode(rawPassword));
    }
}
