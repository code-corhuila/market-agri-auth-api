package co.edu.corhuila.marketagri.auth.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.edu.corhuila.marketagri.auth.application.port.in.ProvisionAdmin;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The start-up step that provisions the initial ADMIN from AUTH_ADMIN_EMAIL and AUTH_ADMIN_PASSWORD
 * (ADR-020 point 8): both or neither (dev and qa have the seed users of auth-db).
 */
class InitialAdminTest {

    private final List<ProvisionAdmin.Command> asked = new ArrayList<>();
    private final ProvisionAdmin provision = command -> {
        asked.add(command);
        return ProvisionAdmin.Outcome.CREATED;
    };

    @Test
    void withoutBothVariablesNothingIsProvisioned() throws Exception {
        new InitialAdmin(provision, "", "").run(null);
        new InitialAdmin(provision, " ", null).run(null);

        assertThat(asked).isEmpty();
    }

    @Test
    void onlyOneOfThemStopsTheStartWithoutPrintingThePassword() {
        assertThatThrownBy(() -> new InitialAdmin(provision, "admin@market-agri.co", "").run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("AUTH_ADMIN_PASSWORD");
        assertThatThrownBy(() -> new InitialAdmin(provision, "", "Admin-de-main-2026").run(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("AUTH_ADMIN_EMAIL")
                .hasMessageNotContaining("Admin-de-main-2026");
        assertThat(asked).isEmpty();
    }

    @Test
    void withBothTheAdminIsProvisioned() throws Exception {
        new InitialAdmin(provision, "admin@market-agri.co", "Admin-de-main-2026").run(null);

        assertThat(asked).containsExactly(new ProvisionAdmin.Command("admin@market-agri.co", "Admin-de-main-2026"));
    }
}
