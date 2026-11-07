package co.edu.corhuila.marketagri.auth.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;

import co.edu.corhuila.marketagri.auth.domain.model.PasswordHash;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/** bcrypt behind the PasswordVerifier port (INV-003): the hashes of auth-db, cost 12. */
class BcryptPasswordVerifierTest {

    /** The seed hash of Ana Ruiz in auth-db (password Productor123, development only). */
    private static final PasswordHash ANA = new PasswordHash("$2a$12$yHcEDghcNSsOFt4XSsWEWO0AVS2aUhwG.ZAjAu4hfONWrdvM4lnSC");

    private final BcryptPasswordVerifier verifier = new BcryptPasswordVerifier();

    @Test
    void theRightPasswordMatchesItsHash() {
        assertThat(verifier.matches("Productor123", ANA)).isTrue();
    }

    @Test
    void anyOtherPasswordDoesNot() {
        assertThat(verifier.matches("productor123", ANA)).isFalse();
        assertThat(verifier.matches("", ANA)).isFalse();
    }

    @Test
    void aHashThatIsNotBcryptNeverMatches() {
        assertThat(verifier.matches("Productor123", new PasswordHash("Productor123"))).isFalse();
    }

    @Test
    void verifyNothingSpendsARealBcryptCheck() {
        // FR-002: the answer for an unknown email takes as long as a wrong password. Cost 12 takes
        // well over 50 ms on any machine; an empty method would take microseconds.
        long start = System.nanoTime();
        verifier.verifyNothing("Productor123");
        Duration spent = Duration.ofNanos(System.nanoTime() - start);

        assertThat(spent).isGreaterThan(Duration.ofMillis(50));
    }

    @Test
    void aNewHashIsBcryptOfCost12ThatAuthDbAcceptsAndMatchesOnlyItsPassword() {
        PasswordHash hash = verifier.hash("Comprador123");

        // The CHECK of user_account.password_hash in auth-db (INV-003).
        assertThat(hash.value()).matches("^\\$2[aby]\\$(1[2-9]|2[0-9]|3[01])\\$[./A-Za-z0-9]{53}$");
        assertThat(hash.value()).startsWith("$2a$12$");
        assertThat(verifier.matches("Comprador123", hash)).isTrue();
        assertThat(verifier.matches("Comprador124", hash)).isFalse();
        assertThat(verifier.hash("Comprador123")).isNotEqualTo(hash);  // a new salt every time
    }
}
