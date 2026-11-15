package co.edu.corhuila.marketagri.auth.domain.model;

import java.math.BigInteger;

/**
 * The public half of the key auth signs with, as E-05 publishes it (ADR-020 point 2): an RSA public
 * key is only its modulus and its public exponent, named by the {@code kid} of the token header.
 */
public record PublicSigningKey(String keyId, BigInteger modulus, BigInteger exponent) {

    public PublicSigningKey {
        if (keyId == null || keyId.isBlank()) {
            throw new IllegalArgumentException("the signing key needs its kid");
        }
        if (modulus == null || modulus.signum() <= 0 || exponent == null || exponent.signum() <= 0) {
            throw new IllegalArgumentException("modulus and exponent must be positive");
        }
    }
}
