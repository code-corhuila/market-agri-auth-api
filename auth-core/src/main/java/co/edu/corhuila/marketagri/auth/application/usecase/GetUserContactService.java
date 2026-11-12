package co.edu.corhuila.marketagri.auth.application.usecase;

import co.edu.corhuila.marketagri.auth.application.port.in.GetUserContact;
import co.edu.corhuila.marketagri.auth.application.port.out.UserProfiles;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import co.edu.corhuila.marketagri.auth.domain.model.UserNotFoundException;
import java.util.UUID;

/** I-07: only a SERVICE token reaches it (D-C27), so the only rule left is existence. */
public final class GetUserContactService implements GetUserContact {

    private final UserProfiles profiles;

    public GetUserContactService(UserProfiles profiles) {
        this.profiles = profiles;
    }

    @Override
    public User get(UUID userId) {
        return profiles.findActiveById(userId).orElseThrow(UserNotFoundException::new);
    }
}
