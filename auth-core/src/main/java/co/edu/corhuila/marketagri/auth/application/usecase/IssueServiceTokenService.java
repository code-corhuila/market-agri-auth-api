package co.edu.corhuila.marketagri.auth.application.usecase;

import co.edu.corhuila.marketagri.auth.application.port.in.IssueServiceToken;
import co.edu.corhuila.marketagri.auth.application.port.out.ServiceClients;
import co.edu.corhuila.marketagri.auth.application.port.out.ServiceTokens;
import co.edu.corhuila.marketagri.auth.domain.model.InvalidClientCredentialsException;
import co.edu.corhuila.marketagri.auth.domain.model.ServiceClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * I-01 (HU-PLAT-002): known client credentials get a service token of 30 days, kept as the caller's
 * SERVICE_TOKEN secret (ADR-020 point 5); every failure is the same {@code INVALID_CLIENT_CREDENTIALS}.
 */
public class IssueServiceTokenService implements IssueServiceToken {

    static final Duration SERVICE_TOKEN_LIFETIME = Duration.ofDays(30);

    private final ServiceClients clients;
    private final ServiceTokens tokens;
    private final Clock clock;

    public IssueServiceTokenService(ServiceClients clients, ServiceTokens tokens, Clock clock) {
        this.clients = clients;
        this.tokens = tokens;
        this.clock = clock;
    }

    @Override
    public ServiceToken issue(Command command) {
        ServiceClient client = clients.authenticate(command.clientId(), command.clientSecret())
                .orElseThrow(InvalidClientCredentialsException::new);
        // The token carries seconds (iat, exp), so expiresAt is the same instant as exp.
        Instant issuedAt = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresAt = issuedAt.plus(SERVICE_TOKEN_LIFETIME);
        return new ServiceToken(tokens.signService(client, issuedAt, expiresAt), expiresAt);
    }
}
