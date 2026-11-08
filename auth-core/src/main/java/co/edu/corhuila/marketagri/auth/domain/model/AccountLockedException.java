package co.edu.corhuila.marketagri.auth.domain.model;

/** E-02 row 4: 5 consecutive failed logins lock the account for 15 minutes, even with the right password (FR-009). */
public class AccountLockedException extends DomainException {

    public AccountLockedException() {
        super("ACCOUNT_LOCKED", "account locked after consecutive failed logins");
    }
}
