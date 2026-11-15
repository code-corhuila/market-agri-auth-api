package co.edu.corhuila.marketagri.auth.application.port.out;

import co.edu.corhuila.marketagri.auth.domain.model.PublicSigningKey;

/** The key the tokens are signed with; only its public half leaves the adapter (ADR-020 point 1). */
public interface SigningKeys {

    PublicSigningKey current();
}
