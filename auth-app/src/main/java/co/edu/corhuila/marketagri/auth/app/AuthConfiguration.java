package co.edu.corhuila.marketagri.auth.app;

import co.edu.corhuila.marketagri.auth.adapter.out.persistence.JdbcDatabaseCheck;
import co.edu.corhuila.marketagri.auth.adapter.out.persistence.JdbcRefreshTokens;
import co.edu.corhuila.marketagri.auth.adapter.out.persistence.JdbcUserAccounts;
import co.edu.corhuila.marketagri.auth.adapter.out.persistence.JdbcUserRegistrations;
import co.edu.corhuila.marketagri.auth.adapter.out.persistence.SpringUnitOfWork;
import co.edu.corhuila.marketagri.auth.adapter.out.security.BcryptPasswordVerifier;
import co.edu.corhuila.marketagri.auth.adapter.out.security.ConfiguredServiceClients;
import co.edu.corhuila.marketagri.auth.adapter.out.security.PrivateKeys;
import co.edu.corhuila.marketagri.auth.adapter.out.security.Rs256AccessTokens;
import co.edu.corhuila.marketagri.auth.adapter.out.security.RsaSigningKeys;
import co.edu.corhuila.marketagri.auth.application.port.in.IssueServiceToken;
import co.edu.corhuila.marketagri.auth.application.port.in.LogIn;
import co.edu.corhuila.marketagri.auth.application.port.in.PublishSigningKey;
import co.edu.corhuila.marketagri.auth.application.port.in.Register;
import co.edu.corhuila.marketagri.auth.application.port.out.ReadinessCheck;
import co.edu.corhuila.marketagri.auth.application.port.out.RefreshTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.ServiceClients;
import co.edu.corhuila.marketagri.auth.application.port.out.SigningKeys;
import co.edu.corhuila.marketagri.auth.application.port.out.UnitOfWork;
import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import co.edu.corhuila.marketagri.auth.application.port.out.UserRegistrations;
import co.edu.corhuila.marketagri.auth.application.usecase.IssueServiceTokenService;
import co.edu.corhuila.marketagri.auth.application.usecase.LogInService;
import co.edu.corhuila.marketagri.auth.application.usecase.PublishSigningKeyService;
import co.edu.corhuila.marketagri.auth.application.usecase.RegisterService;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.Clock;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

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

    /** bcrypt for the login and the registration (ports PasswordVerifier and PasswordHasher): one bean. */
    @Bean
    BcryptPasswordVerifier passwords() {
        return new BcryptPasswordVerifier();
    }

    @Bean
    UserRegistrations userRegistrations(JdbcClient jdbc) {
        return new JdbcUserRegistrations(jdbc);
    }

    @Bean
    UnitOfWork unitOfWork(PlatformTransactionManager transactionManager) {
        return new SpringUnitOfWork(new TransactionTemplate(transactionManager));
    }

    /**
     * The private key auth signs with (ADR-020 point 1), read once from the file infra mounts.
     * Without it the service does not start.
     */
    @Bean
    PrivateKey signingPrivateKey(@Value("${auth.jwt.private-key-file:}") String privateKeyFile) {
        if (privateKeyFile.isBlank()) {
            throw new IllegalStateException("Set AUTH_JWT_PRIVATE_KEY_FILE");
        }
        return PrivateKeys.fromFile(Path.of(privateKeyFile));
    }

    /**
     * The signer of the user and the service tokens (ports AccessTokens and ServiceTokens): that key,
     * its kid and the issuer by configuration. One bean, so each port has a single implementation.
     */
    @Bean
    Rs256AccessTokens tokenSigner(PrivateKey signingPrivateKey,
                              @Value("${auth.jwt.key-id:}") String keyId,
                              @Value("${auth.jwt.issuer:}") String issuer) {
        return new Rs256AccessTokens(signingPrivateKey, keyId, issuer);
    }

    /** E-05 publishes the public half of the same key, with the same kid (ADR-020 point 2). */
    @Bean
    SigningKeys signingKeys(PrivateKey signingPrivateKey, @Value("${auth.jwt.key-id:}") String keyId) {
        return new RsaSigningKeys(signingPrivateKey, keyId);
    }

    @Bean
    PublishSigningKey publishSigningKey(SigningKeys signingKeys) {
        return new PublishSigningKeyService(signingKeys);
    }

    @Bean
    LogIn logIn(UserAccounts accounts, BcryptPasswordVerifier passwords, Rs256AccessTokens tokenSigner,
                RefreshTokens refreshTokens) {
        return new LogInService(accounts, passwords, tokenSigner, refreshTokens, Clock.systemUTC());
    }

    /** E-01: the user and its Idempotency-Key in one transaction (D-C35). */
    @Bean
    Register register(UserRegistrations registrations, BcryptPasswordVerifier passwords, UnitOfWork unitOfWork) {
        return new RegisterService(registrations, passwords, unitOfWork);
    }

    /** The callers of I-01 (ADR-020 points 5 and 8): AUTH_SERVICE_CLIENTS, an environment secret. */
    @Bean
    ServiceClients serviceClients(@Value("${auth.service-clients:}") String configuration) {
        return new ConfiguredServiceClients(configuration);
    }

    @Bean
    IssueServiceToken issueServiceToken(ServiceClients serviceClients, Rs256AccessTokens tokenSigner) {
        return new IssueServiceTokenService(serviceClients, tokenSigner, Clock.systemUTC());
    }
}
