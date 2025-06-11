package apikeycloak.tokenization.dto;

public class UsuarioRequest {

    private String username;
    private String email;
    private String nombre;     // firstName
    private String apellido;   // lastName
    private String telefono;
    private String rol;
    private String password;

    // 🔹 Constructor vacío
    public UsuarioRequest() {
    }

    // 🔹 Constructor con todos los campos
    public UsuarioRequest(String username, String email, String nombre, String apellido, String telefono, String rol, String password) {
        this.username = username;
        this.email = email;
        this.nombre = nombre;
        this.apellido = apellido;
        this.telefono = telefono;
        this.rol = rol;
        this.password = password;
    }

    // 🔹 Getters y Setters

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

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getApellido() {
        return apellido;
    }

    public void setApellido(String apellido) {
        this.apellido = apellido;
    }

    public String getTelefono() {
        return telefono;
    }

    public void setTelefono(String telefono) {
        this.telefono = telefono;
    }

    public String getRol() {
        return rol;
    }

    public void setRol(String rol) {
        this.rol = rol;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
