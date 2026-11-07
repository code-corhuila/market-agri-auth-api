package co.edu.corhuila.marketagri.auth.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.domain.model.PublicSigningKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import org.junit.jupiter.api.Test;

/** The public half comes from the private key auth signs with, so E-05 cannot publish another key (ADR-020). */
class RsaSigningKeysTest {

    @Test
    void derivesThePublicHalfOfThePrivateKeyWithItsKid() throws Exception {
        KeyPair pair = pair();
        RSAPublicKey expected = (RSAPublicKey) pair.getPublic();

        PublicSigningKey key = new RsaSigningKeys(pair.getPrivate(), "kid-1").current();

        assertThat(key.keyId()).isEqualTo("kid-1");
        assertThat(key.modulus()).isEqualTo(expected.getModulus());
        assertThat(key.exponent()).isEqualTo(expected.getPublicExponent());
    }

    @Test
    void aPrivateKeyWithoutItsPublicHalfStopsTheService() throws Exception {
        RSAPrivateKey full = (RSAPrivateKey) pair().getPrivate();
        PrivateKey bare = KeyFactory.getInstance("RSA")
                .generatePrivate(new RSAPrivateKeySpec(full.getModulus(), full.getPrivateExponent()));

        assertThatThrownBy(() -> new RsaSigningKeys(bare, "kid-1")).isInstanceOf(IllegalStateException.class);
    }

    private static KeyPair pair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
