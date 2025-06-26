package apikeycloak.tokenization.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import apikeycloak.tokenization.config.KeycloakProperties;
import apikeycloak.tokenization.dto.KeycloakUserResponse;
import apikeycloak.tokenization.dto.UsuarioRequest;
import apikeycloak.tokenization.exception.KeycloakApiException;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service
public class KeycloakUserService {

    private final KeycloakProperties keycloakProperties;
    private final WebClient webClient;

    public KeycloakUserService(WebClient webClient, KeycloakProperties keycloakProperties) {
        this.webClient = webClient;
        this.keycloakProperties = keycloakProperties;
    }

    // Crear usuario (con rol y contraseña)
    public void crearUsuario(UsuarioRequest request) {
        log.info("Inicio creación usuario: {}", request.getUsername());
        log.debug("Datos recibidos: firstName={}, lastName={}, email={}, rol={}, password=****, attributes={}", 
              request.getFirstName(), request.getLastName(), request.getEmail(), request.getRol(), request.getAttributes());

        // Validar que usuario no exista
        if (usuarioExiste(request.getUsername())) {
            log.warn("El usuario {} ya existe", request.getUsername());
            throw new KeycloakApiException("El usuario ya existe en Keycloak.");
        }

        String token = obtenerTokenAdmin();  // Puede lanzar excepción
        log.debug("Token admin obtenido");

        try {
            String userId = crearUsuarioEnKeycloak(token, request);
            log.info("Usuario creado en Keycloak con ID: {}", userId);

            if (request.getRol() != null && !request.getRol().isEmpty()) {
                log.debug("Intentando asignar rol: {}", request.getRol());
                asignarRol(token, userId, request.getRol(), keycloakProperties.getClientName());
                log.info("Rol '{}' asignado al usuario '{}'", request.getRol(), userId);
            }

            if (request.getPassword() != null && !request.getPassword().isEmpty()) {
                log.debug("Estableciendo contraseña para usuario");
                establecerPassword(token, userId, request.getPassword());
                log.info("Contraseña establecida para usuario '{}'", userId);
            }

        } catch (Exception e) {
            log.error("Error durante creación de usuario '{}': {}", request.getUsername(), e.getMessage(), e);
            throw new KeycloakApiException("Error al crear usuario en Keycloak");
        }
    }

    private boolean usuarioExiste(String username) {
        List<KeycloakUserResponse> usuariosExistentes = listarUsuarios(username);
        return usuariosExistentes != null && !usuariosExistentes.isEmpty();
    }

    private String crearUsuarioEnKeycloak(String token, UsuarioRequest request) {
        Map<String, Object> userCreate = new HashMap<>();
        userCreate.put("username", request.getUsername());
        userCreate.put("firstName", request.getFirstName());
        userCreate.put("lastName", request.getLastName());
        userCreate.put("email", request.getEmail());
        userCreate.put("emailVerified", request.getEmailVerified() != null ? request.getEmailVerified() : false);
        userCreate.put("enabled", true);
        userCreate.put("attributes", request.getAttributes() != null ? request.getAttributes() : Map.of());

        var response = webClient.post()
            .uri(keycloakProperties.getAdminUrl() + "/users")
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(userCreate)
            .retrieve()
            .toBodilessEntity()
            .block();

        if (response == null || response.getStatusCode().value() != 201) {
            throw new KeycloakApiException("Error creando usuario en Keycloak");
        }

        String location = response.getHeaders().getLocation().toString();
        return location.substring(location.lastIndexOf("/") + 1);
    }

    // Obtener token admin (con clientId y secret configurados)
    private String obtenerTokenAdmin() {
        log.debug("Obteniendo token admin para Keycloak");

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");
        params.add("client_id", keycloakProperties.getClientId());
        params.add("client_secret", keycloakProperties.getClientSecret());

        try {
            Map<String, Object> tokenResponse = webClient.post()
                .uri(keycloakProperties.getTokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(params))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();

            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                log.error("No se obtuvo access_token en la respuesta del token admin");
                throw new KeycloakApiException("Error al obtener el token de administración");
            }

            return (String) tokenResponse.get("access_token");
        } catch (Exception e) {
            log.error("Error obteniendo token admin: {}", e.getMessage(), e);
            throw new KeycloakApiException("Error al obtener el token de administración");
        }
    }

    // Asignar rol a usuario para cliente específico
    private void asignarRol(String token, String userId, String rolNombre, String clientName) {
        log.debug("Asignando rol '{}' al usuario con ID '{}' para cliente '{}'", rolNombre, userId, clientName);
        try {
            List<Map<String, Object>> clients = webClient.get()
                .uri(keycloakProperties.getAdminUrl() + "/clients")
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                .block();

            if (clients == null) {
                throw new KeycloakApiException("No se pudieron obtener los clientes de Keycloak");
            }

            String clientId = clients.stream()
                .filter(c -> clientName.equals(c.get("clientId")))
                .map(c -> (String) c.get("id"))
                .findFirst()
                .orElseThrow(() -> new KeycloakApiException("No se encontró el cliente " + clientName));

            List<Map<String, Object>> roles = webClient.get()
                .uri(keycloakProperties.getAdminUrl() + "/clients/" + clientId + "/roles")
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                .block();

            if (roles == null) {
                throw new KeycloakApiException("No se pudieron obtener los roles del cliente");
            }

            Map<String, Object> rol = roles.stream()
                .filter(r -> rolNombre.equals(r.get("name")))
                .findFirst()
                .orElseThrow(() -> new KeycloakApiException("Rol no encontrado: " + rolNombre));

            webClient.post()
                .uri(keycloakProperties.getAdminUrl() + "/users/" + userId + "/role-mappings/clients/" + clientId)
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(List.of(rol))
                .retrieve()
                .toBodilessEntity()
                .block();

            log.info("Rol '{}' asignado correctamente al usuario '{}'", rolNombre, userId);

        } catch (Exception e) {
            log.error("Error asignando rol al usuario '{}': {}", userId, e.getMessage(), e);
            throw new KeycloakApiException("Error al asignar rol al usuario");
        }
    }

    // Establecer password a usuario
    private void establecerPassword(String token, String userId, String password) {
        log.debug("Estableciendo password para usuario ID: {}", userId);

        try {
            Map<String, Object> passwordPayload = Map.of(
                "type", "password",
                "temporary", false,
                "value", password
            );

            webClient.put()
                .uri(keycloakProperties.getAdminUrl() + "/users/" + userId + "/reset-password")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(passwordPayload)
                .retrieve()
                .toBodilessEntity()
                .block();

            log.info("Contraseña asignada correctamente al usuario con ID: {}", userId);
        } catch (Exception e) {
            log.error("Error asignando contraseña al usuario: {}", userId, e);
            throw new KeycloakApiException("Error al asignar la contraseña al usuario.");
        }
    }

    // Listar usuarios por username
    public List<KeycloakUserResponse> listarUsuarios(String username) {
        log.debug("Listando usuarios con username: {}", username);

        if (username == null || username.isEmpty()) {
            log.debug("Username vacío, devolviendo lista vacía");
            return List.of();
        }
        String token = obtenerTokenAdmin();
        String url = keycloakProperties.getAdminUrl() + "/users?username=" + username;

        try {
            List<KeycloakUserResponse> usuarios = webClient.get()
                .uri(url)
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<KeycloakUserResponse>>() {})
                .block();

            if (usuarios == null) {
                throw new KeycloakApiException("Error al obtener la lista de usuarios por username de Keycloak");
            }

            return usuarios;
        } catch (Exception e) {
            throw new KeycloakApiException("Error al listar usuarios por username", e);
        }
    }

    // Eliminar roles asignados a usuario (para un cliente específico)
    private void eliminarRolesUsuario(String token, String userId, String clientName) {
        log.debug("Eliminando roles asignados al usuario con ID: {} para cliente: {}", userId, clientName);

        try {
            List<Map<String, Object>> clients = webClient.get()
                .uri(keycloakProperties.getAdminUrl() + "/clients")
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                .block();

            String clientId = clients.stream()
                .filter(c -> clientName.equals(c.get("clientId")))
                .map(c -> (String) c.get("id"))
                .findFirst()
                .orElseThrow(() -> new KeycloakApiException("No se encontró el cliente " + clientName));

            List<Map<String, Object>> rolesAsignados = webClient.get()
                .uri(keycloakProperties.getAdminUrl() + "/users/" + userId + "/role-mappings/clients/" + clientId)
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                .block();

            if (rolesAsignados == null || rolesAsignados.isEmpty()) {
                log.info("No hay roles asignados al usuario para el cliente: {}", clientName);
                return;
            }

           webClient.method(HttpMethod.DELETE)
            .uri(keycloakProperties.getAdminUrl() + "/users/" + userId + "/role-mappings/clients/" + clientId)
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(rolesAsignados)
            .retrieve()
            .toBodilessEntity()
            .block();

            log.info("Roles eliminados correctamente para el usuario con ID: {}", userId);

        } catch (Exception e) {
            log.error("Error eliminando roles para usuario '{}': {}", userId, e.getMessage(), e);
            throw new KeycloakApiException("Error al eliminar roles del usuario");
        }
    }

    // Método público para eliminar roles (que recibe userId y clientName)
    public void eliminarRolesUsuarioPublico(String userId, String clientName) {
        String token = obtenerTokenAdmin();
        eliminarRolesUsuario(token, userId, clientName);
    }

    public void asignarRolAdmin(String userId, String rolNombre) {
        String token = obtenerTokenAdmin();
        asignarRol(token, userId, rolNombre, keycloakProperties.getClientName());
    }

    public List<Map<String, Object>> listarUsuariosGenerico() {
        String token = obtenerTokenAdmin();
        try {
            List<Map<String, Object>> usuarios = webClient.get()
                .uri(keycloakProperties.getAdminUrl() + "/users")
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                .block();

            return usuarios != null ? usuarios : List.of();
        } catch (Exception e) {
            throw new KeycloakApiException("Error al listar usuarios genéricos", e);
        }
    }

    public void actualizarUsuario(String userId, UsuarioRequest usuarioRequest) {
        String token = obtenerTokenAdmin();

        Map<String, Object> updatePayload = new HashMap<>();
        updatePayload.put("firstName", usuarioRequest.getFirstName());
        updatePayload.put("lastName", usuarioRequest.getLastName());
        updatePayload.put("email", usuarioRequest.getEmail());
        updatePayload.put("enabled", true);
        // Añade más campos si quieres

        try {
            webClient.put()
                .uri(keycloakProperties.getAdminUrl() + "/users/" + userId)
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(updatePayload)
                .retrieve()
                .toBodilessEntity()
                .block();
        } catch (Exception e) {
            throw new KeycloakApiException("Error al actualizar usuario", e);
        }
    }

    public List<Map<String, Object>> obtenerRolesDelCliente(String token) {
        String clientName = keycloakProperties.getClientName(); // Obtenido desde application.properties

        List<Map<String, Object>> clients = webClient.get()
            .uri(keycloakProperties.getAdminUrl() + "/clients")
            .header("Authorization", "Bearer " + token)
            .retrieve()
            .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
            .block();

        if (clients == null) {
            throw new RuntimeException("No se pudo obtener la lista de clientes");
        }

        String clientId = clients.stream()
            .filter(c -> clientName.equals(c.get("clientId")))
            .map(c -> (String) c.get("id"))
            .findFirst()
            .orElseThrow(() -> new RuntimeException("No se encontró el cliente configurado: " + clientName));

        List<Map<String, Object>> rolesCliente = webClient.get()
            .uri(keycloakProperties.getAdminUrl() + "/clients/" + clientId + "/roles")
            .header("Authorization", "Bearer " + token)
            .retrieve()
            .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
            .block();

        return rolesCliente;
    }



}