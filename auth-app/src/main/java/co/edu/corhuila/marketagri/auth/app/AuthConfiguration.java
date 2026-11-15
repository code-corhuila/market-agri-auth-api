package co.edu.corhuila.marketagri.auth.app;

import co.edu.corhuila.marketagri.auth.adapter.in.http.PublicKeys;
import co.edu.corhuila.marketagri.auth.adapter.in.http.Rs256Verifier;
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
import co.edu.corhuila.marketagri.auth.application.port.in.GetUser;
import co.edu.corhuila.marketagri.auth.application.port.in.IssueServiceToken;
import co.edu.corhuila.marketagri.auth.application.port.in.LogIn;
import co.edu.corhuila.marketagri.auth.application.port.in.ProvisionAdmin;
import co.edu.corhuila.marketagri.auth.application.port.in.PublishSigningKey;
import co.edu.corhuila.marketagri.auth.application.port.in.Register;
import co.edu.corhuila.marketagri.auth.application.port.out.ReadinessCheck;
import co.edu.corhuila.marketagri.auth.application.port.out.RefreshTokens;
import co.edu.corhuila.marketagri.auth.application.port.out.ServiceClients;
import co.edu.corhuila.marketagri.auth.application.port.out.SigningKeys;
import co.edu.corhuila.marketagri.auth.application.port.out.UnitOfWork;
import co.edu.corhuila.marketagri.auth.application.port.out.UserAccounts;
import co.edu.corhuila.marketagri.auth.application.port.out.UserProfiles;
import co.edu.corhuila.marketagri.auth.application.port.out.UserRegistrations;
import co.edu.corhuila.marketagri.auth.application.usecase.GetUserService;
import co.edu.corhuila.marketagri.auth.application.usecase.IssueServiceTokenService;
import co.edu.corhuila.marketagri.auth.application.usecase.LogInService;
import co.edu.corhuila.marketagri.auth.application.usecase.ProvisionAdminService;
import co.edu.corhuila.marketagri.auth.application.usecase.PublishSigningKeyService;
import co.edu.corhuila.marketagri.auth.application.usecase.RegisterService;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
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

    /** The users of auth-db for the login (UserAccounts) and for E-08 (UserProfiles): one bean. */
    @Bean
    JdbcUserAccounts userAccounts(JdbcClient jdbc) {
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

    /** E-08: the user themselves or ADMIN. */
    @Bean
    GetUser getUser(UserProfiles profiles) {
        return new GetUserService(profiles);
    }

    /** FR-008: the initial ADMIN, from a path the team operates (ADR-020 point 8). */
    @Bean
    ProvisionAdmin provisionAdmin(UserAccounts accounts, UserRegistrations registrations,
                                  BcryptPasswordVerifier passwords) {
        return new ProvisionAdminService(accounts, registrations, passwords);
    }

    @Bean
    ApplicationRunner initialAdmin(ProvisionAdmin provisionAdmin,
                                   @Value("${auth.admin.email:}") String email,
                                   @Value("${auth.admin.password:}") String password) {
        return new InitialAdmin(provisionAdmin, email, password);
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

    /**
     * Validator of the tokens that reach auth (ADR-020 point 2, Anexo C 5.3.7), as in every service:
     * the public key by configuration, JWT_PUBLIC_KEY first, JWT_PUBLIC_KEY_FILE otherwise. It must be
     * the public half of the signing key; without it, or with another one, the service does not start.
     */
    @Bean
    Rs256Verifier tokenVerifier(SigningKeys signingKeys,
                                @Value("${auth.jwt.issuer:}") String issuer,
                                @Value("${auth.jwt.public-key:}") String publicKey,
                                @Value("${auth.jwt.public-key-file:}") String publicKeyFile) {
        RSAPublicKey key;
        if (!publicKey.isBlank()) {
            key = PublicKeys.fromPem(publicKey);
        } else if (!publicKeyFile.isBlank()) {
            key = PublicKeys.fromFile(Path.of(publicKeyFile));
        } else {
            throw new IllegalStateException("Set JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_FILE");
        }
        return new Rs256Verifier(PublicKeys.pairedWith(key, signingKeys.current()), issuer, Clock.systemUTC());
    }
}
