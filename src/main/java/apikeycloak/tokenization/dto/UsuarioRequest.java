package apikeycloak.tokenization.dto;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.Map;

public class UsuarioRequest {

    @NotBlank(message = "El username es obligatorio")
    private String username;
    @NotBlank(message = "El nombre es obligatorio")
    private String firstName;
    private String lastName;
    @Email(message = "El email debe ser válido")
    @NotBlank(message = "El email es obligatorio")
    private String email;
    private Boolean emailVerified = false;
    private Map<String, List<String>> attributes;
    @Size(min = 6, message = "La contraseña debe tener al menos 6 caracteres")
    private String password;
    private String rol;
    private Boolean enabled = true;

    public UsuarioRequest() {
    }

    public UsuarioRequest(String username, String firstName, String lastName, String email, Boolean emailVerified,
                          Map<String, List<String>> attributes, String password, String rol, Boolean enabled) {
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.emailVerified = emailVerified;
        this.attributes = attributes;
        this.password = password;
        this.rol = rol;
        this.enabled = enabled;
    }


    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
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

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(Boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public Map<String, List<String>> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, List<String>> attributes) {
        this.attributes = attributes;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRol() {
        return rol;
    }

    public void setRol(String rol) {
        this.rol = rol;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public String getTelefono() {
        if (attributes != null && attributes.containsKey("telefono")) {
            List<String> telefonos = attributes.get("telefono");
            if (telefonos != null && !telefonos.isEmpty()) {
                return telefonos.get(0);
            }
        }
        return null;
    }
}