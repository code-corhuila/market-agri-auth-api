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
}
