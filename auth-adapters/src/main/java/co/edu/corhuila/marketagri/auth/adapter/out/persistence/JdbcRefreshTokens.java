package co.edu.corhuila.marketagri.auth.adapter.out.persistence;

import co.edu.corhuila.marketagri.auth.application.port.out.RefreshTokens;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;

/** {@code refresh_token} of auth-db (D-C2): a new random token, of which only the hash is stored. */
public final class JdbcRefreshTokens implements RefreshTokens {

    private final JdbcClient jdbc;

    public JdbcRefreshTokens(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public String issue(UUID userId, Instant issuedAt, Instant expiresAt) {
        String token = OpaqueTokens.newToken();
        jdbc.sql("""
                        INSERT INTO refresh_token (user_id, token_hash, expires_at, created_at)
                        VALUES (:userId, :tokenHash, :expiresAt, :createdAt)
                        """)
                .param("userId", userId)
                .param("tokenHash", OpaqueTokens.sha256Hex(token))
                .param("expiresAt", Timestamp.from(expiresAt))
                .param("createdAt", Timestamp.from(issuedAt))
                .update();
        return token;
    }
}
