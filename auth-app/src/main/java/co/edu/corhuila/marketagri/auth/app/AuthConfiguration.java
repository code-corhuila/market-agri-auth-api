package co.edu.corhuila.marketagri.auth.app;

import co.edu.corhuila.marketagri.auth.adapter.out.persistence.JdbcDatabaseCheck;
import co.edu.corhuila.marketagri.auth.adapter.out.persistence.JdbcRefreshTokens;
import co.edu.corhuila.marketagri.auth.adapter.out.persistence.JdbcUserAccounts;
import co.edu.corhuila.marketagri.auth.adapter.out.security.BcryptPasswordVerifier;
import co.edu.corhuila.marketagri.auth.adapter.out.security.PrivateKeys;
import co.edu.corhuila.marketagri.auth.adapter.out.security.Rs256AccessTokens;
import co.edu.corhuila.marketagri.auth.application.port.in.LogIn;
import co.edu.corhuila.marketagri.auth.application.port.out.AccessTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.PasswordVerifier;
import co.edu.corhuila.marketagri.auth.application.port.out.ReadinessCheck;
import co.edu.corhuila.marketagri.auth.application.port.out.RefreshTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import co.edu.corhuila.marketagri.auth.application.usecase.LogInService;
import java.nio.file.Path;
import java.time.Clock;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * The only place that knows the concrete types: use cases of the core are wired to the
 * outbound adapters here, with {@code @Bean} methods.
 */
@Configuration
public class AuthConfiguration {

    /** E-61: auth answers only with its database up. */
    @Bean
    ReadinessCheck databaseCheck(DataSource dataSource) {
        return new JdbcDatabaseCheck(dataSource);
    }

    @Bean
    UserAccounts userAccounts(JdbcClient jdbc) {
        return new JdbcUserAccounts(jdbc);
    }

    @Bean
    RefreshTokens refreshTokens(JdbcClient jdbc) {
        return new JdbcRefreshTokens(jdbc);
    }

    @Bean
    PasswordVerifier passwordVerifier() {
        return new BcryptPasswordVerifier();
    }

    /**
     * The signer of the tokens (ADR-020 point 1): the private key from the file infra mounts, its kid
     * and the issuer by configuration. Without any of them the service does not start.
     */
    @Bean
    AccessTokens accessTokens(@Value("${auth.jwt.private-key-file:}") String privateKeyFile,
                              @Value("${auth.jwt.key-id:}") String keyId,
                              @Value("${auth.jwt.issuer:}") String issuer) {
        if (privateKeyFile.isBlank()) {
            throw new IllegalStateException("Set AUTH_JWT_PRIVATE_KEY_FILE");
        }
        return new Rs256AccessTokens(PrivateKeys.fromFile(Path.of(privateKeyFile)), keyId, issuer);
    }

    @Bean
    LogIn logIn(UserAccounts accounts, PasswordVerifier passwords, AccessTokens accessTokens,
                RefreshTokens refreshTokens) {
        return new LogInService(accounts, passwords, accessTokens, refreshTokens, Clock.systemUTC());
    }
}
