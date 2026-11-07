package co.edu.corhuila.marketagri.auth.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.domain.model.ServiceClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * AUTH_SERVICE_CLIENTS (authentication.md §7): {@code clientId:clientSecretHash} pairs separated by
 * commas, the hash being the SHA-256 of the secret in lowercase hex, as for the refresh tokens.
 */
class ConfiguredServiceClientsTest {

    private static final String WORKFLOW_HASH = sha256("secreto-de-workflow");

    /** What the operator runs: {@code printf %s "$SECRET" | sha256sum}. */
    private static String sha256(String secret) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    @Test
    void theRightSecretAuthenticatesItsClient() {
        var clients = new ConfiguredServiceClients(
                "workflow:" + WORKFLOW_HASH + ", worker:" + sha256("secreto-de-worker"));

        assertThat(clients.authenticate("workflow", "secreto-de-workflow")).isEqualTo(Optional.of(new ServiceClient("workflow")));
        assertThat(clients.authenticate("worker", "secreto-de-worker")).isEqualTo(Optional.of(new ServiceClient("worker")));
    }

    @Test
    void aWrongSecretAnUnknownClientOrAnotherClientsSecretAuthenticateNobody() {
        var clients = new ConfiguredServiceClients(
                "workflow:" + sha256("secreto-de-workflow") + ",worker:" + sha256("secreto-de-worker"));

        assertThat(clients.authenticate("workflow", "otro")).isEmpty();
        assertThat(clients.authenticate("workflow", "secreto-de-worker")).isEmpty();
        assertThat(clients.authenticate("chat", "secreto-de-workflow")).isEmpty();
        assertThat(clients.authenticate("workflow", sha256("secreto-de-workflow"))).isEmpty();
    }

    @Test
    void withoutClientsNobodyGetsAToken() {
        assertThat(new ConfiguredServiceClients("").authenticate("workflow", "secreto-de-workflow")).isEmpty();
        assertThat(new ConfiguredServiceClients(null).authenticate("workflow", "secreto-de-workflow")).isEmpty();
    }

    @Test
    void aMalformedEntryStopsTheServiceWithoutPrintingTheHash() {
        String shortHash = WORKFLOW_HASH.substring(1);
        for (String config : new String[] {"workflow", "workflow:" + shortHash, "Workflow:" + WORKFLOW_HASH,
                "workflow:" + WORKFLOW_HASH.toUpperCase(), "workflow:" + WORKFLOW_HASH + ",workflow:" + WORKFLOW_HASH}) {
            assertThatThrownBy(() -> new ConfiguredServiceClients(config))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("AUTH_SERVICE_CLIENTS")
                    .hasMessageNotContaining(shortHash.substring(0, 16))
                    .hasMessageNotContaining(shortHash.substring(0, 16).toUpperCase());
        }
    }
}
