package co.edu.corhuila.marketagri.auth.adapter.in.http;

/** A header or a parameter out of range: {@code 400 VALIDATION_ERROR} naming it (D-C35, D-C24). */
final class InvalidParameterException extends RuntimeException {

    private final String field;

    InvalidParameterException(String field, String message) {
        super(message);
        this.field = field;
    }

    String field() {
        return field;
    }
}
