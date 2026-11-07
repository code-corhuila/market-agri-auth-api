package co.edu.corhuila.marketagri.auth.adapter.in.http;

import java.util.Arrays;
import java.util.Optional;
import org.springframework.http.HttpStatus;

/** Codes of the auth rules (api-contract §4.1: E-01, E-02, E-08, I-01), with their status and Spanish message. */
enum DomainError {
    VALIDATION_ERROR(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR.message()),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "Correo o contraseña incorrectos."),
    ROLE_NOT_ALLOWED(HttpStatus.UNPROCESSABLE_ENTITY, "No es posible registrarse con el rol ADMIN."),
    EMAIL_ALREADY_REGISTERED(HttpStatus.CONFLICT, "El correo ya está registrado."),
    FORBIDDEN(HttpStatus.FORBIDDEN, ErrorCode.FORBIDDEN.message()),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "El usuario no existe."),
    INVALID_CLIENT_CREDENTIALS(HttpStatus.UNAUTHORIZED, "Credenciales de servicio inválidas.");

    private final HttpStatus status;
    private final String message;

    DomainError(HttpStatus status, String message) {
        this.status = status;
        this.message = message;
    }

    HttpStatus status() {
        return status;
    }

    String message() {
        return message;
    }

    static Optional<DomainError> of(String code) {
        return Arrays.stream(values()).filter(error -> error.name().equals(code)).findFirst();
    }
}
