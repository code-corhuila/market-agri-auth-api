package co.edu.corhuila.marketagri.auth.application.usecase;

import static org.assertj.core.api.Assertions.assertThat;

import co.edu.corhuila.marketagri.auth.domain.model.PublicSigningKey;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;

/** E-05 in the core (HU-PLAT-002): it publishes the public half of the key the tokens are signed with. */
class PublishSigningKeyServiceTest {

    @Test
    void publishesThePublicHalfOfTheKeyTheTokensAreSignedWith() {
        PublicSigningKey key = new PublicSigningKey("kid-1", BigInteger.valueOf(3233), BigInteger.valueOf(17));

        assertThat(new PublishSigningKeyService(() -> key).publicKey()).isEqualTo(key);
    }
}
