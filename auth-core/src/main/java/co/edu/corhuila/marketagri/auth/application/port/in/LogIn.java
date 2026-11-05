package co.edu.corhuila.marketagri.auth.application.port.in;

import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.time.Instant;

/** E-02: a registered user gets a session (HU-AUTH-002, D-C2, D-C3). */
public interface LogIn {

    /** A session, or {@code InvalidCredentialsException} for every failure (rows 3 and 5 of the card). */
    Session logIn(Command command);

    /** What the person typed; the HTTP adapter already refused a missing or empty field. */
    record Command(String email, String password) {

        @Override
        public String toString() {
            return "LogIn.Command[email=" + email + ", password=***]";
        }
    }

    /** {@code expiresAt} is the expiry of the access token (issue + 60 min). */
    record Session(String accessToken, Instant expiresAt, String refreshToken, User user) {
    }
}
