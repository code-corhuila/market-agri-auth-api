package co.edu.corhuila.marketagri.auth.application.usecase;

import co.edu.corhuila.marketagri.auth.application.port.in.PublishSigningKey;
import co.edu.corhuila.marketagri.auth.application.port.out.SigningKeys;
import co.edu.corhuila.marketagri.auth.domain.model.PublicSigningKey;

/** E-05 (HU-PLAT-002): publishes the public half of the key the tokens are signed with, and nothing else. */
public class PublishSigningKeyService implements PublishSigningKey {

    private final SigningKeys signingKeys;

    public PublishSigningKeyService(SigningKeys signingKeys) {
        this.signingKeys = signingKeys;
    }

    @Override
    public PublicSigningKey publicKey() {
        return signingKeys.current();
    }
}
