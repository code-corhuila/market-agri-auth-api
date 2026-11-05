package co.edu.corhuila.marketagri.auth.domain.model;

/** A name or an email that breaks the rules of a user ({@code 400}); the HTTP adapter checks the shape first. */
public class InvalidUserException extends DomainException {

    public InvalidUserException(String message) {
        super("VALIDATION_ERROR", message);
    }
}
