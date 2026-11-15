package co.edu.corhuila.marketagri.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/** A caller of /internal/** (ADR-020 point 5): its token says who it is with sub = service:<name>. */
class ServiceClientTest {

    @Test
    void theSubjectOfItsTokenIsServiceAndItsName() {
        assertThat(new ServiceClient("workflow").subject()).isEqualTo("service:workflow");
    }

    @Test
    void aNameThatCouldBreakTheSubjectOrTheConfigurationIsRefused() {
        for (String name : new String[] {null, "", " ", "Workflow", "work:flow", "work flow", "work,flow"}) {
            assertThatThrownBy(() -> new ServiceClient(name)).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
