package co.edu.corhuila.marketagri.auth.adapter.out.security;

import co.edu.corhuila.marketagri.auth.application.port.out.SigningKeys;
import co.edu.corhuila.marketagri.auth.domain.model.PublicSigningKey;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;

/**
 * Derives the public half from the private key auth signs with: a PKCS#8 RSA key (the one dev-keys.sh
 * writes) carries the modulus and the public exponent, so E-05 cannot publish a different key and no
 * second variable is needed. Without them the service does not start.
 */
public final class RsaSigningKeys implements SigningKeys {

    private final PublicSigningKey publicKey;

    public RsaSigningKeys(PrivateKey privateKey, String keyId) {
        if (!(privateKey instanceof RSAPrivateCrtKey rsa)) {
            throw new IllegalStateException("The JWT private key has no public half: a PKCS#8 RSA key is expected");
        }
        this.publicKey = new PublicSigningKey(keyId, rsa.getModulus(), rsa.getPublicExponent());
    }

    @Override
    public PublicSigningKey current() {
        return publicKey;
    }
}
