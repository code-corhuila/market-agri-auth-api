package co.edu.corhuila.marketagri.auth.adapter.in.http;

import co.edu.corhuila.marketagri.auth.adapter.in.http.LoginController.UserView;
import co.edu.corhuila.marketagri.auth.application.port.in.GetUser;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * E-08 {@code GET /api/v1/auth/users/{id}}: the {@code UserView} for the user themselves or ADMIN.
 * A user token is required (a SERVICE token is 403 in the interceptor, D-C27); an {@code {id}} that
 * is not a UUID is 400 (D-C23).
 */
@RestController
@RequestMapping("/api/v1/auth/users")
public class UserController {

    private final GetUser getUser;

    public UserController(GetUser getUser) {
        this.getUser = getUser;
    }

    @GetMapping("/{id}")
    public UserView get(@RequestAttribute(Caller.ATTRIBUTE) Caller caller, @PathVariable UUID id) {
        return UserView.of(getUser.get(new GetUser.Query(caller.userId(), Role.valueOf(caller.role()), id)));
    }
}
