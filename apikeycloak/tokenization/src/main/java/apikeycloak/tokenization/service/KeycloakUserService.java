package apikeycloak.tokenization.service;

import java.util.List;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
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

    public void crearUsuario(UsuarioRequest request) {
        log.info("Iniciando creación de usuario: {}", request.getUsername());

        String token = obtenerTokenAdmin();

        // Validar existencia por username
        List<KeycloakUserResponse> existingUsersByUsername = listarUsuarios(request.getUsername());
        if (existingUsersByUsername != null && !existingUsersByUsername.isEmpty()) {
            log.warn("Ya existe un usuario con username: {}", request.getUsername());
            throw new KeycloakApiException("El usuario con username '" + request.getUsername() + "' ya existe.");
        }

        // Validar existencia por email
        List<KeycloakUserResponse> existingUsersByEmail = listarUsuariosPorEmail(request.getEmail());
        if (existingUsersByEmail != null && !existingUsersByEmail.isEmpty()) {
            log.warn("Ya existe un usuario con email: {}", request.getEmail());
            throw new KeycloakApiException("El usuario con email '" + request.getEmail() + "' ya existe.");
        }

        try {
            Map<String, Object> user = Map.of(
                    "enabled", true,
                    "username", request.getUsername(),
                    "email", request.getEmail(),
                    "firstName", request.getNombre()
            );

            var createUserResponse = webClient.post()
                    .uri(keycloakProperties.getAdminUrl() + "/users")
                    .header("Authorization", "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(user)
                    .retrieve()
                    .toBodilessEntity()
                    .block();

            if (createUserResponse == null || createUserResponse.getStatusCode().value() != 201) {
                log.error("Falló la creación del usuario. Respuesta: {}", createUserResponse);
                throw new KeycloakApiException("Error al crear el usuario en Keycloak.");
            }

            log.info("Usuario creado exitosamente: {}", request.getUsername());
        } catch (Exception e) {
            log.error("Excepción durante la creación del usuario: {}", e.getMessage(), e);
            throw new KeycloakApiException("Excepción al crear el usuario en Keycloak.");
        }

        // Buscar usuario recién creado para obtener ID
        String userId = buscarUsuarioIdPorEmail(token, request.getEmail());

        // Asignar contraseña
        establecerPassword(token, userId, request.getPassword());

        // Asignar rol
        asignarRol(token, userId, request.getRol());

        log.info("Usuario {} creado y configurado correctamente con rol {}", request.getUsername(), request.getRol());
    }

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
                log.error("Respuesta nula al listar usuarios por username");
                throw new KeycloakApiException("Error al obtener la lista de usuarios por username de Keycloak");
            }

            log.debug("Usuarios encontrados: {}", usuarios.size());
            return usuarios;
        } catch (Exception e) {
            log.error("Error listando usuarios por username: {}", e.getMessage(), e);
            throw new KeycloakApiException("Error al listar usuarios por username");
        }
    }

    public List<KeycloakUserResponse> listarUsuariosPorEmail(String email) {
        log.debug("Listando usuarios con email: {}", email);

        if (email == null || email.isEmpty()) {
            log.debug("Email vacío, devolviendo lista vacía");
            return List.of();
        }
        String token = obtenerTokenAdmin();
        String url = keycloakProperties.getAdminUrl() + "/users?email=" + email;

        try {
            List<KeycloakUserResponse> usuarios = webClient.get()
                    .uri(url)
                    .header("Authorization", "Bearer " + token)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<List<KeycloakUserResponse>>() {})
                    .block();

            if (usuarios == null) {
                log.error("Respuesta nula al listar usuarios por email");
                throw new KeycloakApiException("Error al obtener la lista de usuarios por email de Keycloak");
            }

            log.debug("Usuarios encontrados: {}", usuarios.size());
            return usuarios;
        } catch (Exception e) {
            log.error("Error listando usuarios por email: {}", e.getMessage(), e);
            throw new KeycloakApiException("Error al listar usuarios por email");
        }
    }

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

            log.debug("Token admin obtenido correctamente");
            return (String) tokenResponse.get("access_token");
        } catch (Exception e) {
            log.error("Error obteniendo token admin: {}", e.getMessage(), e);
            throw new KeycloakApiException("Error al obtener el token de administración");
        }
    }

    private void asignarRol(String token, String userId, String rolNombre) {
        log.debug("Asignando rol '{}' al usuario con ID '{}'", rolNombre, userId);

        try {
            List<Map<String, Object>> clients = webClient.get()
                    .uri(keycloakProperties.getAdminUrl() + "/clients")
                    .header("Authorization", "Bearer " + token)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                    .block();

            if (clients == null) {
                log.error("No se pudieron obtener los clientes de Keycloak");
                throw new KeycloakApiException("No se pudieron obtener los clientes de Keycloak");
            }

            String clientId = clients.stream()
                    .filter(c -> keycloakProperties.getClientName().equals(c.get("clientId")))
                    .map(c -> (String) c.get("id"))
                    .findFirst()
                    .orElseThrow(() -> new KeycloakApiException("No se encontró el cliente " + keycloakProperties.getClientName()));

            List<Map<String, Object>> roles = webClient.get()
                    .uri(keycloakProperties.getAdminUrl() + "/clients/" + clientId + "/roles")
                    .header("Authorization", "Bearer " + token)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                    .block();

            if (roles == null) {
                log.error("No se pudieron obtener los roles del cliente");
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

    private String buscarUsuarioIdPorEmail(String token, String email) {
        log.debug("Buscando usuario por email: {}", email);

        try {
            String searchUrl = keycloakProperties.getAdminUrl() + "/users?email=" + email;

            List<KeycloakUserResponse> users = webClient.get()
                    .uri(searchUrl)
                    .header("Authorization", "Bearer " + token)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<List<KeycloakUserResponse>>() {})
                    .block();

            if (users == null || users.isEmpty()) {
                log.error("No se encontró el usuario con email: {}", email);
                throw new KeycloakApiException("No se pudo obtener el usuario creado.");
            }

            return users.get(0).getId();
        } catch (Exception e) {
            log.error("Error buscando usuario por email: {}", email, e);
            throw new KeycloakApiException("Error buscando usuario por email.");
        }
    }

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

    public List<Map<String, Object>> listarUsuariosGenerico() {
        log.debug("Listando todos los usuarios");

        String token = obtenerTokenAdmin();

        try {
            List<Map<String, Object>> usuarios = webClient.get()
                    .uri(keycloakProperties.getAdminUrl() + "/users")
                    .header("Authorization", "Bearer " + token)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<List<Map<String, Object>>>() {})
                    .block();

            log.debug("Usuarios totales obtenidos: {}", usuarios != null ? usuarios.size() : 0);

            return usuarios;
        } catch (Exception e) {
            log.error("Error listando usuarios: {}", e.getMessage(), e);
            throw new KeycloakApiException("Error al listar usuarios");
        }
    }

    public void asignarRolAdmin(String userId, String rolNombre) {
    String token = obtenerTokenAdmin();
    asignarRol(token, userId, rolNombre);
}

}