package co.edu.corhuila.marketagri.auth.app;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * The key pair of the Spring tests, generated while they run and never versioned (ADR-020 point 7).
 * The private half goes to a temporary file, as infra mounts it from keys/<env>/.
 */
final class TestKeys {

    private static final KeyPair KEYS = generate();
    private static final Path PRIVATE_KEY_FILE = write();

    private TestKeys() {
    }

    static String privateKeyFile() {
        return PRIVATE_KEY_FILE.toString();
    }

    static PublicKey publicKey() {
        return KEYS.getPublic();
    }

    /** For {@link TestTokens}: the tokens a client presents are signed by the same key as auth's. */
    static PrivateKey privateKey() {
        return KEYS.getPrivate();
    }

    private static KeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static Path write() {
        try {
            Path file = Files.createTempFile("auth-test-jwt-private", ".pem");
            file.toFile().deleteOnExit();
            Files.writeString(file, "-----BEGIN PRIVATE KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(KEYS.getPrivate().getEncoded())
                    + "\n-----END PRIVATE KEY-----\n");
            return file;
        } catch (IOException failure) {
            throw new UncheckedIOException(failure);
        }
    }
}
