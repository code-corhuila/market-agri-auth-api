package co.edu.corhuila.marketagri.auth.adapter.out.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** The refresh token of D-C2: random and opaque for the client, only its SHA-256 for the database. */
class OpaqueTokensTest {

    @Test
    void aNewTokenIs256RandomBitsInBase64Url() {
        String token = OpaqueTokens.newToken();

        assertThat(token).matches("[A-Za-z0-9_-]{43}");
        assertThat(OpaqueTokens.newToken()).isNotEqualTo(token);
    }

    @Test
    void theHashIsTheSha256InLowercaseHex() {
        // Test vector of FIPS 180-2 for "abc".
        assertThat(OpaqueTokens.sha256Hex("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void theHashHasTheShapeAuthDbAccepts() {
        assertThat(OpaqueTokens.sha256Hex(OpaqueTokens.newToken())).matches("[0-9a-f]{64}");
    }
}
