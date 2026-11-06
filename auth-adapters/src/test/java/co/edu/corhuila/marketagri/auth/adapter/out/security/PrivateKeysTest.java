package co.edu.corhuila.marketagri.auth.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The private key auth-api signs with, read from the file infra mounts (ADR-020, keys/<env>/). */
class PrivateKeysTest {

    @TempDir
    Path dir;

    @Test
    void readsThePkcs8PemThatDevKeysWrites() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        RSAPrivateKey key = (RSAPrivateKey) generator.generateKeyPair().getPrivate();
        Path file = dir.resolve("jwt-private.pem");
        Files.writeString(file, "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getEncoded())
                + "\n-----END PRIVATE KEY-----\n");

        assertThat(PrivateKeys.fromFile(file)).isEqualTo(key);
    }

    @Test
    void aMissingFileStopsTheServiceWithAClearMessage() {
        assertThatThrownBy(() -> PrivateKeys.fromFile(dir.resolve("missing.pem")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("missing.pem");
    }

    @Test
    void aFileThatIsNotAPrivateKeyIsRefused() throws Exception {
        Path file = dir.resolve("not-a-key.pem");
        Files.writeString(file, "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n");

        assertThatThrownBy(() -> PrivateKeys.fromFile(file)).isInstanceOf(IllegalStateException.class);
    }
}
