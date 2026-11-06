package co.edu.corhuila.marketagri.auth.app;

import co.edu.corhuila.marketagri.auth.adapter.out.persistence.JdbcDatabaseCheck;
import co.edu.corhuila.marketagri.auth.adapter.out.persistence.JdbcRefreshTokens;
import co.edu.corhuila.marketagri.auth.adapter.out.persistence.JdbcUserAccounts;
import co.edu.corhuila.marketagri.auth.application.port.out.ReadinessCheck;
import co.edu.corhuila.marketagri.auth.application.port.out.RefreshTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import javax.sql.DataSource;
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
}
