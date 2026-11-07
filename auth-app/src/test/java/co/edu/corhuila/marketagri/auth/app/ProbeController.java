package co.edu.corhuila.marketagri.auth.app;

import co.edu.corhuila.marketagri.auth.adapter.in.http.PublicEndpoint;
import co.edu.corhuila.marketagri.auth.domain.model.DomainException;
import co.edu.corhuila.marketagri.auth.domain.model.InvalidCredentialsException;
import java.util.Map;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test-only routes for the cross-cutting HTTP adapter (error body, validation, correlation, domain
 * codes). They stay after the real endpoints exist: they test the handler and the filter on their
 * own. They live in the test sources, so they never reach the jar. Anonymous, so the token never
 * hides the check under test; the token checks use {@link SecuredProbeController}.
 */
@PublicEndpoint
@RestController
public class ProbeController {

    public record ProbeRequest(@NotBlank(message = "Es obligatorio.") String email,
                               @NotBlank(message = "Es obligatorio.") String password) {
    }

    @PostMapping("/probe")
    public Map<String, String> create(@RequestHeader("Idempotency-Key") String key,
                                      @Valid @RequestBody ProbeRequest request) {
        return Map.of("email", request.email());
    }

    @GetMapping("/probe/{id}")
    public Map<String, String> read(@PathVariable UUID id) {
        return Map.of("id", id.toString());
    }

    @GetMapping("/probe/failure")
    public Map<String, String> failure() {
        throw new IllegalStateException("SELECT * FROM auth.secret_table");
    }

    @GetMapping("/probe/invalid-credentials")
    public Map<String, String> invalidCredentials() {
        throw new InvalidCredentialsException();
    }

    @GetMapping("/probe/unknown-domain-code")
    public Map<String, String> unknownDomainCode() {
        throw new DomainException("NOT_IN_THE_CONTRACT", "a code without a row in DomainError");
    }
}
