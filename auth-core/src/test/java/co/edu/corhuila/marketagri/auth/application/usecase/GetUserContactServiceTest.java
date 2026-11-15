package co.edu.corhuila.marketagri.auth.application.usecase;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.domain.model.DomainException;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * I-07 in the core (ADR-016): the worker reads a recipient's contact. Only a SERVICE token reaches
 * it (the interceptor checks that), so the only rule left is existence.
 */
class GetUserContactServiceTest {

    private static final User ANA = new User(UUID.fromString("0b6f2c7e-4a51-4c1e-9d0e-2f1c3a7b9e10"), "Ana Ruiz",
            Email.of("productor@market-agri.test"), new PasswordHash("x"), Role.PRODUCER);

    private final GetUserContactService service =
            new GetUserContactService(id -> id.equals(ANA.id()) ? Optional.of(ANA) : Optional.empty());

    @Test
    void anExistingUserIsFound() {
        assertThat(service.get(ANA.id())).isEqualTo(ANA);
    }

    @Test
    void anUnknownUserIsUserNotFound() {
        assertThatThrownBy(() -> service.get(UUID.randomUUID()))
                .isInstanceOfSatisfying(DomainException.class,
                        failure -> assertThat(failure.code()).isEqualTo("USER_NOT_FOUND"));
    }
}
