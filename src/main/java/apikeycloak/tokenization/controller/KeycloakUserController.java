package apikeycloak.tokenization.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono; 
import apikeycloak.tokenization.client.KeycloakAdminClient;
import apikeycloak.tokenization.config.KeycloakProperties;
import apikeycloak.tokenization.dto.KeycloakUserResponse;
import apikeycloak.tokenization.dto.UsuarioRequest;
import apikeycloak.tokenization.service.KeycloakUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.Collections; 
import com.fasterxml.jackson.databind.ObjectMapper;


@RestController
@RequestMapping("/api/keycloak/users")
public class KeycloakUserController {

    private final KeycloakUserService keycloakUserService;
    private final KeycloakAdminClient keycloakAdminClient;
    private final KeycloakProperties keycloakProperties; 
    private final ObjectMapper objectMapper; 

    public KeycloakUserController(
            KeycloakUserService keycloakUserService,
            KeycloakAdminClient keycloakAdminClient,
            KeycloakProperties keycloakProperties,
            ObjectMapper objectMapper) {
        this.keycloakUserService = keycloakUserService;
        this.keycloakAdminClient = keycloakAdminClient; 
        this.keycloakProperties = keycloakProperties;
        this.objectMapper = objectMapper;
    }
    
    @PostMapping("/create")   
    //@PreAuthorize("hasRole('ADMIN')") // <-- ¡AÑADE ESTO AQUÍ!
    @PreAuthorize("hasAnyRole('ADMIN', 'VETERINARIO', 'ASISTENTE')")
    public ResponseEntity<?> crearUsuario(@Valid @RequestBody UsuarioRequest usuarioRequest,
                                         HttpServletRequest request) { 
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

        } else {

        }

        try {
            keycloakUserService.crearUsuario(usuarioRequest);
            Map<String, String> successResponse = Collections.singletonMap("message", "Usuario creado exitosamente");
            try {
                String jsonResponse = objectMapper.writeValueAsString(successResponse);
                System.out.println(jsonResponse);
            } catch (Exception e) {
                System.err.println("Error al serializar la respuesta JSON de éxito para depuración: " + e.getMessage());
            }

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Collections.singletonMap("message", "Usuario creado exitosamente"));
        } catch (RuntimeException e) {
            Map<String, String> errorResponse = Collections.singletonMap("error", e.getMessage());
            try {
                String jsonResponse = objectMapper.writeValueAsString(errorResponse);
                System.out.println(jsonResponse);
            } catch (Exception ex) {
                System.err.println("Error al serializar la respuesta JSON de error para depuración: " + ex.getMessage());
            }
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Collections.singletonMap("error", e.getMessage()));
        }
    }

    @GetMapping
    //@PreAuthorize("hasRole('ADMIN')") 
    @PreAuthorize("hasAnyRole('ADMIN', 'VETERINARIO', 'ASISTENTE')")
    public ResponseEntity<List<KeycloakUserResponse>> listarUsuarios(
            @RequestParam(required = false) String username) {
        List<KeycloakUserResponse> usuarios = keycloakUserService.listarUsuarios(username);
        return ResponseEntity.ok(usuarios);
    }
    
    @PostMapping("/{userId}/roles")
    //@PreAuthorize("hasRole('ADMIN')")
    @PreAuthorize("hasAnyRole('ADMIN', 'VETERINARIO', 'ASISTENTE')")
    public ResponseEntity<?> asignarRol(
            @PathVariable String userId,
            @RequestParam String rol) {
        try {
            keycloakUserService.asignarRolAdmin(userId, rol);
            return ResponseEntity.ok(Collections.singletonMap("message", "Rol asignado correctamente")); // ¡AJUSTADO: consistent JSON!
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Collections.singletonMap("error", e.getMessage()));
        }
    }

    @GetMapping("/all")
    //@PreAuthorize("hasRole('ADMIN')") 
    @PreAuthorize("hasAnyRole('ADMIN', 'VETERINARIO', 'ASISTENTE')")
    public ResponseEntity<List<KeycloakUserResponse>> listarUsuariosGen(
            @RequestParam(required = false) String username) {
        if (username == null || username.isEmpty()) {
            List<KeycloakUserResponse> usuarios = keycloakUserService.listarUsuariosGenerico();
            return ResponseEntity.ok(usuarios);
        } else {
            return ResponseEntity.ok(List.of()); 
        }
    }

    @PutMapping("/{userId}")
    //@PreAuthorize("hasRole('ADMIN')") 
    @PreAuthorize("hasAnyRole('ADMIN', 'VETERINARIO', 'ASISTENTE')")
    public ResponseEntity<?> actualizarUsuario(
            @PathVariable String userId,
            @Valid @RequestBody UsuarioRequest usuarioRequest) {
        try {
            keycloakUserService.actualizarUsuario(userId, usuarioRequest);
            return ResponseEntity.ok(Collections.singletonMap("message", "Usuario actualizado correctamente")); 
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Collections.singletonMap("error", e.getMessage()));
        }
    }

    @GetMapping("/roles") // Endpoint para obtener TODOS los roles del cliente vetcare-app
    //@PreAuthorize("hasRole('ADMIN')") 
    @PreAuthorize("hasAnyRole('ADMIN', 'VETERINARIO', 'ASISTENTE')")
    public Mono<ResponseEntity<List<String>>> listarTodosLosRolesDelClienteKeycloak() {
        System.out.println("--- CONTROLADOR: Solicitando TODOS los roles del CLIENTE Keycloak (Usando WebClient) ---");

        return keycloakAdminClient.getAllRolesForTargetClient()
                .map(roles -> {
                    return ResponseEntity.ok(roles);
                })
                .defaultIfEmpty(ResponseEntity.ok(List.of()))
                .onErrorResume(e -> {
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Collections.singletonList("Error al obtener roles: " + e.getMessage()))); 
                });
    }

    @DeleteMapping("/delete/{userId}")
    //@PreAuthorize("hasRole('ADMIN')") 
    @PreAuthorize("hasAnyRole('ADMIN', 'VETERINARIO', 'ASISTENTE')")
    public ResponseEntity<?> eliminarUsuario(@PathVariable String userId) {
        try {
            keycloakUserService.eliminarUsuario(userId);
            return ResponseEntity.ok(Collections.singletonMap("message", "Usuario eliminado exitosamente."));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Collections.singletonMap("error", "Error al eliminar usuario: " + e.getMessage()));
        }
    }

    /**
     * Endpoint para obtener usuarios por un rol de cliente específico.
     * Requiere el rol 'ADMIN' para acceder.
     * @param roleName El nombre del rol de cliente (ej. "veterinario", "asistente").
     * @return Mono<ResponseEntity<List<Map<String, Object>>>> Una respuesta HTTP con la lista de usuarios.
     */
 
    @GetMapping("/byClientRole/{roleName}")
    //@PreAuthorize("hasRole('ADMIN')") 
    @PreAuthorize("hasAnyRole('ADMIN', 'VETERINARIO', 'ASISTENTE')")
    public Mono<ResponseEntity<List<Map<String, Object>>>> getUsersByClientRole(@PathVariable String roleName) {
        System.out.println("--- CONTROLADOR: Solicitando usuarios con rol de cliente: " + roleName + " ---");
        
        return keycloakAdminClient.getUsersByClientRole(roleName)
                .map(users -> {
                    if (users.isEmpty()) {
                        System.out.println("No se encontraron usuarios con el rol '" + roleName + "'.");
                        @SuppressWarnings("unchecked")
                        List<Map<String, Object>> emptyList = (List<Map<String, Object>>) Collections.EMPTY_LIST;
                        return ResponseEntity.ok(emptyList);
                    }
                    System.out.println("Usuarios con el rol '" + roleName + "' obtenidos: " + users.size());
                    return ResponseEntity.ok(users);
                })
                .onErrorResume(e -> {
                    System.err.println("Error en el controlador al obtener usuarios por rol de cliente '" + roleName + "': " + e.getMessage());
                    List<Map<String, Object>> errorBody = Collections.singletonList(
                        Collections.singletonMap("error", "Error al obtener usuarios por rol: " + e.getMessage())
                    );
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorBody));
                });
    }

    /**
     * Endpoint para obtener usuarios por un rol de REINO específico.
     * Requiere el rol 'ADMIN' para acceder.
     * @param roleName El nombre del rol de reino (ej. "uma_authorization", "offline_access").
     * @return Mono<ResponseEntity<List<Map<String, Object>>>> Una respuesta HTTP con la lista de usuarios.
     */
    @GetMapping("/byRealmRole/{roleName}")
    //@PreAuthorize("hasRole('ADMIN')")
    @PreAuthorize("hasAnyRole('ADMIN', 'VETERINARIO', 'ASISTENTE')")
    public Mono<ResponseEntity<List<Map<String, Object>>>> getUsersByRealmRole(@PathVariable String roleName) {
        System.out.println("--- CONTROLADOR: Solicitando usuarios con rol de reino: " + roleName + " ---");

        return keycloakAdminClient.getUsersByRealmRole(roleName)
                .map(users -> {
                    // Ensure the type is List<Map<String, Object>>
                    List<Map<String, Object>> castedUsers = (List<Map<String, Object>>) users;
                    if (castedUsers == null || castedUsers.isEmpty()) {
                        System.out.println("No se encontraron usuarios con el rol de reino '" + roleName + "'.");
                        return ResponseEntity.ok(Collections.<Map<String, Object>>emptyList());
                    }
                    System.out.println("Usuarios con el rol de reino '" + roleName + "' obtenidos: " + castedUsers.size());
                    return ResponseEntity.ok(castedUsers);
                })
                .onErrorResume(e -> {
                    System.err.println("Error en el controlador al obtener usuarios por rol de reino '" + roleName + "': " + e.getMessage());
                    List<Map<String, Object>> errorBody = Collections.singletonList(
                        Collections.singletonMap("error", "Error al obtener usuarios por rol de reino: " + e.getMessage())
                    );
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorBody));
                });
    }
    
    // NUEVO MÉTODO: BUSCAR USUARIO POR ID
    @GetMapping("/{userId}")
    //@PreAuthorize("hasRole('ADMIN')") 
    @PreAuthorize("hasAnyRole('ADMIN', 'VETERINARIO', 'ASISTENTE')")
    public Mono<ResponseEntity<?>> buscarUsuarioPorId(@PathVariable String userId) {
        System.out.println("--- CONTROLADOR: Solicitando usuario con ID: " + userId + " ---");
        return keycloakUserService.findUserById(userId)
                .map(user -> {
                    if (user != null) {
                        System.out.println("Usuario con ID '" + userId + "' encontrado.");
                        return ResponseEntity.ok(user);
                    } else {
                        System.out.println("Usuario con ID '" + userId + "' no encontrado.");
                        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                                .body(Collections.singletonMap("message", "Usuario no encontrado con ID: " + userId));
                    }
                })
                .onErrorResume(e -> {
                    System.err.println("Error en el controlador al buscar usuario por ID '" + userId + "': " + e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Collections.singletonMap("error", "Error al buscar usuario: " + e.getMessage())));
                });
    }

}
