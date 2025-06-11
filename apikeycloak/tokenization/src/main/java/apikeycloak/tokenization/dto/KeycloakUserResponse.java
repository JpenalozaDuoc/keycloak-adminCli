package apikeycloak.tokenization.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class KeycloakUserResponse {

    private String id;
    private String username;
    private String email;
    private boolean enabled;
    private boolean emailVerified;
    private String firstName;
    private String lastName;

    // Constructores
    public KeycloakUserResponse() {}

    public KeycloakUserResponse(String id, String username, String email, boolean enabled,
                                 boolean emailVerified, String firstName, String lastName) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.enabled = enabled;
        this.emailVerified = emailVerified;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    // Getters y Setters

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    // toString() útil para logs
    @Override
    public String toString() {
        return "KeycloakUserResponse{" +
                "id='" + id + '\'' +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", enabled=" + enabled +
                ", emailVerified=" + emailVerified +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                '}';
    }
}
