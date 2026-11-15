package co.edu.corhuila.marketagri.auth.application.port.out;

import java.time.Instant;
import java.util.UUID;

/**
 * Issues an opaque refresh token for a user (D-C2): the adapter makes it random, stores only its
 * hash and returns the token itself, which only the client keeps.
 */
public interface RefreshTokens {

    String issue(UUID userId, Instant issuedAt, Instant expiresAt);
}
