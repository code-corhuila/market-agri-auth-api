package co.edu.corhuila.marketagri.auth.application.port.out;

import co.edu.corhuila.marketagri.auth.domain.model.ServiceClient;
import java.time.Instant;

/** Signs the token of a service (RS256 in the adapter, ADR-020 point 5): role SERVICE, no name. */
public interface ServiceTokens {

    String signService(ServiceClient client, Instant issuedAt, Instant expiresAt);
}
