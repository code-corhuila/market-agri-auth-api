package co.edu.corhuila.marketagri.auth.application.port.in;

import co.edu.corhuila.marketagri.auth.domain.model.User;
import java.util.UUID;

/** I-07: a user's contact for a service, the recipient's address of a notice (ADR-016). */
public interface GetUserContact {

    User get(UUID userId);
}
