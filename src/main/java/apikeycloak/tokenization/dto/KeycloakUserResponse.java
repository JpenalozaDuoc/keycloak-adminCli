package apikeycloak.tokenization.dto;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;


@JsonIgnoreProperties(ignoreUnknown = true)
public class KeycloakUserResponse {

    private String id;
    private String username;
    private String email;
    private boolean enabled;
    private boolean emailVerified;
    private String firstName;
    private String lastName;

    // Nuevo campo attributes, un Map con arrays de String (como en la respuesta JSON)
    private Map<String, String[]> attributes;

    // Nuevo campo access, con permisos dentro de un objeto Access
    private Access access;

    // Constructores
    public KeycloakUserResponse() {}

    public KeycloakUserResponse(String id, String username, String email, boolean enabled,
                                boolean emailVerified, String firstName, String lastName,
                                Map<String, String[]> attributes, Access access) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.enabled = enabled;
        this.emailVerified = emailVerified;
        this.firstName = firstName;
        this.lastName = lastName;
        this.attributes = attributes;
        this.access = access;
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

    public Map<String, String[]> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String[]> attributes) {
        this.attributes = attributes;
    }

    public Access getAccess() {
        return access;
    }

    public void setAccess(Access access) {
        this.access = access;
    }

    // Método auxiliar para obtener el teléfono
    public String getTelefono() {
        if (attributes != null && attributes.containsKey("telefono")) {
            String[] telefonos = attributes.get("telefono");
            if (telefonos.length > 0) {
                return telefonos[0];
            }
        }
        return null;
    }

    // Clase interna para mapear el objeto access
    public static class Access {
        private boolean manageGroupMembership;
        private boolean view;
        private boolean mapRoles;
        private boolean impersonate;
        private boolean manage;

        public Access() {}

        public boolean isManageGroupMembership() {
            return manageGroupMembership;
        }

        public void setManageGroupMembership(boolean manageGroupMembership) {
            this.manageGroupMembership = manageGroupMembership;
        }

        public boolean isView() {
            return view;
        }

        public void setView(boolean view) {
            this.view = view;
        }

        public boolean isMapRoles() {
            return mapRoles;
        }

        public void setMapRoles(boolean mapRoles) {
            this.mapRoles = mapRoles;
        }

        public boolean isImpersonate() {
            return impersonate;
        }

        public void setImpersonate(boolean impersonate) {
            this.impersonate = impersonate;
        }

        public boolean isManage() {
            return manage;
        }

        public void setManage(boolean manage) {
            this.manage = manage;
        }

        @Override
        public String toString() {
            return "Access{" +
                    "manageGroupMembership=" + manageGroupMembership +
                    ", view=" + view +
                    ", mapRoles=" + mapRoles +
                    ", impersonate=" + impersonate +
                    ", manage=" + manage +
                    '}';
        }
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
                ", attributes=" + attributes +
                ", access=" + access +
                '}';
    }
}
