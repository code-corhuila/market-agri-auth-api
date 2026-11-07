package co.edu.corhuila.marketagri.auth.application.usecase;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.application.port.in.GetUser.Query;
import co.edu.corhuila.marketagri.auth.domain.model.DomainException;
import co.edu.corhuila.marketagri.auth.domain.model.Email;
import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import co.edu.corhuila.marketagri.auth.domain.model.Role;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** E-08 in the core: the user themselves or ADMIN; anyone else 403 before existence, so ids cannot be probed. */
class GetUserServiceTest {

    private static final User ANA = new User(UUID.fromString("0b6f2c7e-4a51-4c1e-9d0e-2f1c3a7b9e10"), "Ana Ruiz",
            Email.of("productor@market-agri.test"), new PasswordHash("x"), Role.PRODUCER);
    private static final UUID OTHER = UUID.fromString("7d3e1f20-9a4b-4c5d-8e6f-0a1b2c3d4e5f");

    private final List<UUID> lookedUp = new ArrayList<>();
    private final GetUserService service = new GetUserService(id -> {
        lookedUp.add(id);
        return id.equals(ANA.id()) ? Optional.of(ANA) : Optional.empty();
    });

    @Test
    void theUserThemselvesGetsTheirOwnUser() {
        assertThat(service.get(new Query(ANA.id(), Role.PRODUCER, ANA.id()))).isEqualTo(ANA);
    }

    @Test
    void anAdminGetsAnyUser() {
        assertThat(service.get(new Query(OTHER, Role.ADMIN, ANA.id()))).isEqualTo(ANA);
    }

    @Test
    void anyoneElseIsForbiddenWhetherTheUserExistsOrNotAndNothingIsLookedUp() {
        for (UUID target : List.of(ANA.id(), UUID.randomUUID())) {
            assertThatThrownBy(() -> service.get(new Query(OTHER, Role.BUYER, target)))
                    .isInstanceOf(DomainException.class)
                    .hasMessageContaining("may not see");
            assertThat(codeOf(new Query(OTHER, Role.PRODUCER, target))).isEqualTo("FORBIDDEN");
        }
        assertThat(lookedUp).isEmpty();
    }

    @Test
    void anAdminAskingForAnUnknownUserGetsUserNotFound() {
        assertThat(codeOf(new Query(OTHER, Role.ADMIN, UUID.randomUUID()))).isEqualTo("USER_NOT_FOUND");
    }

    private String codeOf(Query query) {
        try {
            service.get(query);
            throw new AssertionError("expected a failure");
        } catch (DomainException failure) {
            return failure.code();
        }
    }
}
