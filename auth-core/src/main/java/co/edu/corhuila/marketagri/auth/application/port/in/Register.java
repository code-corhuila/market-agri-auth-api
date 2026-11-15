package co.edu.corhuila.marketagri.auth.application.port.in;

import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;

/** E-01: a visitor creates an account as a producer or a buyer (HU-AUTH-001); no tokens (D-C32). */
public interface Register {

    /** The new user, or the original one when the key was already used (D-C35). */
    Registration register(Command command);

    /** What the person typed; the HTTP adapter already refused a missing field or a bad length. */
    record Command(String name, String email, String password, Role role, String idempotencyKey) {

        @Override
        public String toString() {
            return "Register.Command[name=" + name + ", email=" + email + ", password=***, role=" + role
                    + ", idempotencyKey=" + idempotencyKey + "]";
        }
    }

    /** {@code created} is false for the replay of a used key: 200 instead of 201. */
    record Registration(User user, boolean created) {
    }
}
