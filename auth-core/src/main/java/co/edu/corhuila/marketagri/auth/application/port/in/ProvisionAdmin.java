package co.edu.corhuila.marketagri.auth.application.port.in;

/** FR-008: the initial ADMIN of an environment, provisioned when auth-api starts (ADR-020 point 8). */
public interface ProvisionAdmin {

    Outcome provision(Command command);

    /** AUTH_ADMIN_EMAIL and AUTH_ADMIN_PASSWORD, environment secrets. */
    record Command(String email, String password) {

        @Override
        public String toString() {
            return "ProvisionAdmin.Command[email=" + email + ", password=***]";
        }
    }

    enum Outcome { CREATED, ALREADY_PRESENT }
}
