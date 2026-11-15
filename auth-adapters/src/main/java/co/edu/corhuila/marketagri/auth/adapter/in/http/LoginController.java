package co.edu.corhuila.marketagri.auth.adapter.in.http;

import co.edu.corhuila.marketagri.auth.application.port.in.LogIn;
import co.edu.corhuila.marketagri.auth.domain.model.AccountLockedException;
import co.edu.corhuila.marketagri.auth.domain.model.InvalidCredentialsException;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** E-02 {@code POST /api/v1/auth/login} (HU-AUTH-002): anonymous; the session or one generic 401. */
@PublicEndpoint
@RestController
@RequestMapping("/api/v1/auth")
public class LoginController {

    private static final Logger LOG = LoggerFactory.getLogger(LoginController.class);
    private static final String FORWARDED_FOR = "X-Forwarded-For";

    private final LogIn logIn;

    public LoginController(LogIn logIn) {
        this.logIn = logIn;
    }

    /** Row 2 of the card: a missing or empty field is 400, named in {@code details}. */
    public record LoginRequest(@NotBlank(message = "Es obligatorio.") String email,
                               @NotBlank(message = "Es obligatorio.") String password) {

        @Override
        public String toString() {
            return "LoginRequest[email=" + email + ", password=***]";
        }
    }

    /** {@code UserView} of api-contract §4.1. */
    public record UserView(UUID id, String name, String email, String role) {

        static UserView of(User user) {
            return new UserView(user.id(), user.name(), user.email().value(), user.role().name());
        }
    }

    /** {@code AuthResponse} of D-C3. */
    public record AuthResponse(String accessToken, String refreshToken, Instant expiresAt, UserView user) {
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest body, HttpServletRequest request) {
        try {
            LogIn.Session session = logIn.logIn(new LogIn.Command(body.email(), body.password()));
            return new AuthResponse(session.accessToken(), session.refreshToken(), session.expiresAt(),
                    UserView.of(session.user()));
        } catch (InvalidCredentialsException failed) {
            // NFR-052: who tried (the time is the log's), never the password nor whether the email exists.
            logRefused(request, "Login failed: invalid credentials");
            throw failed;
        } catch (AccountLockedException locked) {
            logRefused(request, "Login refused: account locked");
            throw locked;
        }
    }

    private static void logRefused(HttpServletRequest request, String message) {
        LOG.atWarn()
                .addKeyValue("clientIp", clientIp(request))
                .addKeyValue("userAgent", request.getHeader(HttpHeaders.USER_AGENT))
                .log(message);
    }

    /** The first address the gateway forwarded, or the peer when the request did not pass through it. */
    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader(FORWARDED_FOR);
        return forwarded != null && !forwarded.isBlank() ? forwarded.split(",")[0].strip() : request.getRemoteAddr();
    }
}
