package co.edu.corhuila.marketagri.auth.application.usecase;

import co.edu.corhuila.marketagri.auth.application.port.in.GetUser;
import co.edu.corhuila.marketagri.auth.application.port.out.UserProfiles;
import co.edu.corhuila.marketagri.auth.domain.model.User;
import co.edu.corhuila.marketagri.auth.domain.model.UserNotFoundException;

/** E-08 in the order of its card: 403 for anyone but the user and ADMIN, then 404. */
public final class GetUserService implements GetUser {

    private final UserProfiles profiles;

    public GetUserService(UserProfiles profiles) {
        this.profiles = profiles;
    }

    @Override
    public User get(Query query) {
        User.ensureVisibleTo(query.userId(), query.callerId(), query.callerRole());
        return profiles.findActiveById(query.userId()).orElseThrow(UserNotFoundException::new);
    }
}
