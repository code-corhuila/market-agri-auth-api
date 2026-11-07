package co.edu.corhuila.marketagri.auth.application.port.out;

import co.edu.corhuila.marketagri.auth.domain.model.ServiceClient;
import java.util.Optional;

/** The callers allowed to get a service token (AUTH_SERVICE_CLIENTS); empty for an unknown client or a wrong secret. */
public interface ServiceClients {

    Optional<ServiceClient> authenticate(String clientId, String clientSecret);
}
