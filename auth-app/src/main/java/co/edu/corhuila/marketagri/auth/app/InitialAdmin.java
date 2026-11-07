package co.edu.corhuila.marketagri.auth.app;

import co.edu.corhuila.marketagri.auth.application.port.in.ProvisionAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;

/**
 * Provisions the initial ADMIN when auth-api starts (FR-008, ADR-020 point 8), from
 * AUTH_ADMIN_EMAIL and AUTH_ADMIN_PASSWORD: both or neither. dev and qa leave them empty (the seed
 * users of auth-db include an ADMIN); main sets them as secrets. A failure stops the start.
 */
final class InitialAdmin implements ApplicationRunner {

    private static final Logger LOG = LoggerFactory.getLogger(InitialAdmin.class);

    private final ProvisionAdmin provisionAdmin;
    private final String email;
    private final String password;

    InitialAdmin(ProvisionAdmin provisionAdmin, String email, String password) {
        this.provisionAdmin = provisionAdmin;
        this.email = email == null ? "" : email.strip();
        this.password = password == null ? "" : password;
    }

    @Override
    public void run(ApplicationArguments arguments) {
        if (email.isEmpty() && password.isEmpty()) {
            return;
        }
        if (email.isEmpty() || password.isEmpty()) {
            throw new IllegalStateException("Set both AUTH_ADMIN_EMAIL and AUTH_ADMIN_PASSWORD, or neither");
        }
        ProvisionAdmin.Outcome outcome = provisionAdmin.provision(new ProvisionAdmin.Command(email, password));
        LOG.atInfo().addKeyValue("outcome", outcome).log("Initial ADMIN checked");
    }
}
