package co.edu.corhuila.marketagri.auth.application.port.out;

import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;

/** Turns a new password into the only thing auth-db keeps of it (bcrypt cost 12 in the adapter, INV-003). */
public interface PasswordHasher {

    PasswordHash hash(String rawPassword);
}
