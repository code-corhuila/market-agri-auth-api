package co.edu.corhuila.marketagri.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

/** The public half of the signing key that E-05 publishes (ADR-020 point 2): a kid and two positive numbers. */
class PublicSigningKeyTest {

    private static final BigInteger MODULUS = BigInteger.valueOf(3233);
    private static final BigInteger EXPONENT = BigInteger.valueOf(17);

    @Test
    void aKeyWithoutItsKidIsRefused() {
        assertThatThrownBy(() -> new PublicSigningKey(" ", MODULUS, EXPONENT))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aModulusOrExponentThatIsNotPositiveIsRefused() {
        assertThatThrownBy(() -> new PublicSigningKey("kid-1", BigInteger.ZERO, EXPONENT))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PublicSigningKey("kid-1", MODULUS, BigInteger.valueOf(-17)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
