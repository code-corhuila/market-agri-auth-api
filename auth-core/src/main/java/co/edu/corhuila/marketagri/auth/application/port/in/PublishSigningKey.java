package co.edu.corhuila.marketagri.auth.application.port.in;

import co.edu.corhuila.marketagri.auth.domain.model.PublicSigningKey;

/** E-05: the public half of the signing key, for tooling and rotation; no validator depends on it (ADR-020). */
public interface PublishSigningKey {

    PublicSigningKey publicKey();
}
