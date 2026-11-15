package co.edu.corhuila.marketagri.auth.application.usecase;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.application.port.in.IssueServiceToken.Command;
import co.edu.corhuila.marketagri.auth.application.port.in.IssueServiceToken.ServiceToken;
import co.edu.corhuila.marketagri.auth.application.port.out.ServiceClients;
import co.edu.corhuila.marketagri.auth.application.port.out.ServiceTokens;
import co.edu.corhuila.marketagri.auth.domain.model.DomainException;
import co.edu.corhuila.marketagri.auth.domain.model.InvalidClientCredentialsException;
import co.edu.corhuila.marketagri.auth.domain.model.ServiceClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** I-01 in the core (HU-PLAT-002, ADR-020 point 5): a 30-day token for known credentials, one 401 otherwise. */
class IssueServiceTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-06T15:00:00.789Z");
    private static final ServiceClient WORKFLOW = new ServiceClient("workflow");
    private static final String SECRET = "secreto-de-workflow";

    /** Only workflow with its secret is known. */
    private static final ServiceClients CLIENTS = (clientId, clientSecret) ->
            clientId.equals("workflow") && clientSecret.equals(SECRET) ? Optional.of(WORKFLOW) : Optional.empty();

    /** Records what it was asked to sign. */
    private static final class FakeTokens implements ServiceTokens {
        final List<String> signed = new ArrayList<>();

        @Override
        public String signService(ServiceClient client, Instant issuedAt, Instant expiresAt) {
            String token = client.subject() + "|" + issuedAt + "|" + expiresAt;
            signed.add(token);
            return token;
        }
    }

    private final FakeTokens tokens = new FakeTokens();
    private final IssueServiceTokenService service =
            new IssueServiceTokenService(CLIENTS, tokens, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void knownCredentialsGetATokenOfThirtyDaysInWholeSeconds() {
        ServiceToken token = service.issue(new Command("workflow", SECRET));

        Instant issuedAt = Instant.parse("2026-11-06T15:00:00Z");
        Instant expiresAt = issuedAt.plus(Duration.ofDays(30));
        assertThat(token.accessToken()).isEqualTo("service:workflow|" + issuedAt + "|" + expiresAt);
        assertThat(token.expiresAt()).isEqualTo(expiresAt);
    }

    @Test
    void anUnknownClientAndAWrongSecretAreTheSameFailureAndSignNothing() {
        for (Command wrong : List.of(new Command("worker", SECRET), new Command("workflow", "otro"))) {
            assertThatThrownBy(() -> service.issue(wrong))
                    .isInstanceOf(InvalidClientCredentialsException.class)
                    .isInstanceOf(DomainException.class)
                    .hasMessageContaining("invalid client credentials");
            assertThat(((DomainException) catchFailure(wrong)).code()).isEqualTo("INVALID_CLIENT_CREDENTIALS");
        }
        assertThat(tokens.signed).isEmpty();
    }

    @Test
    void theCommandNeverPrintsTheSecret() {
        assertThat(new Command("workflow", SECRET).toString()).doesNotContain(SECRET);
    }

    private Throwable catchFailure(Command command) {
        try {
            service.issue(command);
            throw new AssertionError("expected a failure");
        } catch (DomainException failure) {
            return failure;
        }
    }
}
