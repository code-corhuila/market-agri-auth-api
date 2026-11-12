package co.edu.corhuila.marketagri.auth.adapter.in.http;

import co.edu.corhuila.marketagri.auth.application.port.in.GetUserContact;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * I-07 {@code GET /internal/v1/auth/users/{id}/contact} (ADR-016): the worker reads where to send
 * a notice. Under {@code /internal/} the interceptor only lets a SERVICE token in (D-C27), so no
 * {@link RequiredRole} is needed; the gateway never routes it. The answer carries the address and
 * the name, never the role or the hash.
 */
@RestController
@RequestMapping("/internal/v1/auth/users")
public class UserContactController {

    private final GetUserContact getUserContact;

    public UserContactController(GetUserContact getUserContact) {
        this.getUserContact = getUserContact;
    }

    /** {@code ContactView} of I-07. */
    public record ContactView(UUID id, String email, String name) {

        static ContactView of(User user) {
            return new ContactView(user.id(), user.email().value(), user.name());
        }
    }

    @GetMapping("/{id}/contact")
    public ContactView get(@PathVariable UUID id) {
        return ContactView.of(getUserContact.get(id));
    }
}
