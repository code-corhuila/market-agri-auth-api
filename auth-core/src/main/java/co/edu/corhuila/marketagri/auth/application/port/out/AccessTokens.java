package co.edu.corhuila.marketagri.auth.application.port.out;

import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.time.Instant;

/** Signs the access token of a user (RS256 in the adapter, ADR-020; claims of D-C3). */
public interface AccessTokens {

    String sign(User user, Instant issuedAt, Instant expiresAt);
}
