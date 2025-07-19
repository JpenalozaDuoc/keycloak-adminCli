package apikeycloak.tokenization.dto;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@JsonIgnoreProperties(ignoreUnknown = true)
public class KeycloakUserResponse {

    private String id;
    private String username;
    private String email;
    private Boolean  enabled;
    private Boolean  emailVerified;
    private String firstName;
    private String lastName;
    private Map<String, List<String>> attributes;
    private Access access;
    private String rol;

    public KeycloakUserResponse() {}

    public KeycloakUserResponse(String id, String username, String email, Boolean enabled,
                                Boolean emailVerified, String firstName, String lastName,
                                Map<String, List<String>> attributes) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.enabled = enabled;
        this.emailVerified = emailVerified;
        this.firstName = firstName;
        this.lastName = lastName;
        this.attributes = attributes;
    }

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
        this.attributes = (attributes != null) ? convertStringArrayMapToList(attributes) : null;
        this.access = access;
    }

    private Map<String, List<String>> convertStringArrayMapToList(Map<String, String[]> stringArrayMap) {
        return stringArrayMap.entrySet().stream()
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    entry -> List.of(entry.getValue()) 
                ));
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public Boolean getEnabled() { return enabled; } 
    public void setEnabled(Boolean enabled) { this.enabled = enabled; } 
    public Boolean getEmailVerified() { return emailVerified; } 
    public void setEmailVerified(Boolean emailVerified) { this.emailVerified = emailVerified; } 
    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    public Map<String, List<String>> getAttributes() { return attributes; } 
    public void setAttributes(Map<String, List<String>> attributes) { this.attributes = attributes; } 
    public Access getAccess() { return access; }
    public void setAccess(Access access) { this.access = access; }
    public String getRol() { return rol; }
    public void setRol(String rol) { this.rol = rol; }
    
    public String getTelefono() {
        if (attributes != null && attributes.containsKey("telefono")) {
            List<String> telefonos = attributes.get("telefono");
            if (telefonos != null && !telefonos.isEmpty()) {
                return telefonos.get(0);
            }
        }
        return null;
    }

    public static class Access {
        private boolean manageGroupMembership;
        private boolean view;
        private boolean mapRoles;
        private boolean impersonate;
        private boolean manage;
        public Access() {}
        public boolean isManageGroupMembership() { return manageGroupMembership; }
        public void setManageGroupMembership(boolean manageGroupMembership) { this.manageGroupMembership = manageGroupMembership; }
        public boolean isView() { return view; }
        public void setView(boolean view) { this.view = view; }
        public boolean isMapRoles() { return mapRoles; }
        public void setMapRoles(boolean mapRoles) { this.mapRoles = mapRoles; }
        public boolean isImpersonate() { return impersonate; }
        public void setImpersonate(boolean impersonate) { this.impersonate = impersonate; }
        public boolean isManage() { return manage; }
        public void setManage(boolean manage) { this.manage = manage; }

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
