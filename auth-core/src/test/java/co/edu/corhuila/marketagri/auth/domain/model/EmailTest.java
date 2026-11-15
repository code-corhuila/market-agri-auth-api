package co.edu.corhuila.marketagri.auth.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/** The login credential (INV-002): one account per email, so the same address is always one value. */
class EmailTest {

    @Test
    void isTrimmedAndLowerCasedBeforeAnyComparison() {
        assertThat(Email.of("  Productor@Market-Agri.TEST ").value()).isEqualTo("productor@market-agri.test");
        assertThat(Email.of("Ana@Finca.co")).isEqualTo(Email.of("ana@finca.co"));
    }

    @Test
    void refusesAnEmptyValue() {
        assertThatThrownBy(() -> Email.of("   ")).isInstanceOf(InvalidUserException.class);
        assertThatThrownBy(() -> Email.of(null)).isInstanceOf(InvalidUserException.class);
    }

    @Test
    void refusesAValueThatIsNotAnEmail() {
        assertThatThrownBy(() -> Email.of("ana.finca.co")).isInstanceOf(InvalidUserException.class);
        assertThatThrownBy(() -> Email.of("ana @finca.co")).isInstanceOf(InvalidUserException.class);
        assertThatThrownBy(() -> Email.of("ana@")).isInstanceOf(InvalidUserException.class);
    }

    @Test
    void refusesMoreThan255Characters() {
        String local = "a".repeat(250);
        assertThat(Email.of(local + "@x.co").value()).hasSize(255);
        assertThatThrownBy(() -> Email.of(local + "a@x.co")).isInstanceOf(InvalidUserException.class);
    }

    @Test
    void anInvalidEmailIsAValidationError() {
        assertThatThrownBy(() -> Email.of("sin-arroba"))
                .isInstanceOf(DomainException.class)
                .hasFieldOrPropertyWithValue("code", "VALIDATION_ERROR");
    }
}
