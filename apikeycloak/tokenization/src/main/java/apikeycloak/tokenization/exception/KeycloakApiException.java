package apikeycloak.tokenization.exception;

public class KeycloakApiException extends RuntimeException{

    public KeycloakApiException(String message) {
        super(message);
    }

    public KeycloakApiException(String message, Throwable cause) {
        super(message, cause);
    }
}
