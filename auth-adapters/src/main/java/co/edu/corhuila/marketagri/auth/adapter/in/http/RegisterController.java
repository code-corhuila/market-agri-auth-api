package co.edu.corhuila.marketagri.auth.adapter.in.http;

import co.edu.corhuila.marketagri.auth.adapter.in.http.LoginController.UserView;
import co.edu.corhuila.marketagri.auth.application.port.in.Register;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * E-01 {@code POST /api/v1/auth/register} (HU-AUTH-001): anonymous; {@code 201} with the user and
 * its {@code Location} (E-08), or {@code 200} with the original user when the key was used (D-C35).
 * No tokens: the client logs in with E-02 (D-C32). The body is the {@code UserView} of E-02.
 */
@PublicEndpoint
@RestController
@RequestMapping("/api/v1/auth")
public class RegisterController {

    private static final Logger LOG = LoggerFactory.getLogger(RegisterController.class);
    private static final String IDEMPOTENCY_KEY = "Idempotency-Key";
    private static final int KEY_MIN = 8;
    private static final int KEY_MAX = 128;
    private static final String USERS = "/api/v1/auth/users/";

    private final Register register;

    public RegisterController(Register register) {
        this.register = register;
    }

    /**
     * Row 1 of the card: shape and length. A role other than the three is 400; ADMIN reaches the
     * core, which answers 422 (row 2). Name and email rules after trimming live in the core.
     */
    public record RegisterRequest(
            @NotBlank(message = "Es obligatorio.") String name,
            @NotBlank(message = "Es obligatorio.") @Size(max = 255, message = "Máximo 255 caracteres.") String email,
            @NotNull(message = "Es obligatorio.")
            @Size(min = 8, max = 100, message = "Debe tener entre 8 y 100 caracteres.") String password,
            @NotNull(message = "Es obligatorio.")
            @Pattern(regexp = "PRODUCER|BUYER|ADMIN", message = "Debe ser PRODUCER o BUYER.") String role) {

        @Override
        public String toString() {
            return "RegisterRequest[name=" + name + ", email=" + email + ", password=***, role=" + role + "]";
        }
    }

    @PostMapping("/register")
    public ResponseEntity<UserView> register(@RequestHeader(IDEMPOTENCY_KEY) String idempotencyKey,
                                             @Valid @RequestBody RegisterRequest body) {
        if (idempotencyKey.length() < KEY_MIN || idempotencyKey.length() > KEY_MAX) {
            throw new InvalidParameterException(IDEMPOTENCY_KEY,
                    "Debe tener entre " + KEY_MIN + " y " + KEY_MAX + " caracteres.");
        }
        Register.Registration registration = register.register(new Register.Command(
                body.name(), body.email(), body.password(), Role.valueOf(body.role()), idempotencyKey));
        UserView view = UserView.of(registration.user());
        if (!registration.created()) {
            return ResponseEntity.ok(view);
        }
        LOG.atInfo().addKeyValue("userId", view.id()).addKeyValue("role", view.role()).log("User registered");
        return ResponseEntity.created(URI.create(USERS + view.id())).body(view);
    }
}
