package co.edu.corhuila.marketagri.auth.app;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Base of every Spring test of this module: the composition root does not start without the
 * private key auth signs with and the public key it validates with, so each run gets the pair of
 * {@link TestKeys}, generated while it runs.
 */
abstract class AuthSpringTest {

    @DynamicPropertySource
    static void signingKey(DynamicPropertyRegistry registry) {
        registry.add("auth.jwt.private-key-file", TestKeys::privateKeyFile);
        registry.add("auth.jwt.public-key", TestTokens::publicKeyOnOneLine);
    }
}
