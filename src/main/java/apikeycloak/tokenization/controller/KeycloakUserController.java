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
import reactor.core.publisher.Mono; // <-- Agrega esta línea
import apikeycloak.tokenization.client.KeycloakAdminClient;
import apikeycloak.tokenization.config.KeycloakProperties;// <-- Necesario para obtener targetClientId en el log
import apikeycloak.tokenization.dto.KeycloakUserResponse;
import apikeycloak.tokenization.dto.UsuarioRequest;
import apikeycloak.tokenization.service.KeycloakUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.Collections; // ¡Añade esta línea!
import com.fasterxml.jackson.databind.ObjectMapper;


@RestController
@RequestMapping("/api/keycloak/users")
public class KeycloakUserController {

    private final KeycloakUserService keycloakUserService;
    private final KeycloakAdminClient keycloakAdminClient;
    private final KeycloakProperties keycloakProperties; 
    private final ObjectMapper objectMapper; // <-- Declara ObjectMapper aquí

    public KeycloakUserController(
            KeycloakUserService keycloakUserService,
            KeycloakAdminClient keycloakAdminClient,
            KeycloakProperties keycloakProperties,
            ObjectMapper objectMapper) {
        this.keycloakUserService = keycloakUserService;
        this.keycloakAdminClient = keycloakAdminClient; // <-- Asignar
        this.keycloakProperties = keycloakProperties; // <-- Asignar
        this.objectMapper = objectMapper;
    }

    // Crear usuario
    /*@PostMapping("/create")   
    @PreAuthorize("hasRole('ADMIN')") // <-- ¡AÑADE ESTO AQUÍ!
    public ResponseEntity<?> crearUsuario2(@Valid @RequestBody UsuarioRequest usuarioRequest) {
        try {
            keycloakUserService.crearUsuario(usuarioRequest);
            return ResponseEntity.status(HttpStatus.CREATED).body("Usuario creado exitosamente");
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        }
    }*/
    
    @PostMapping("/create")   
    @PreAuthorize("hasRole('ADMIN')") // <-- ¡AÑADE ESTO AQUÍ!
    public ResponseEntity<?> crearUsuario(@Valid @RequestBody UsuarioRequest usuarioRequest,
                                         HttpServletRequest request) { // ¡Añade HttpServletRequest aquí!
        // --- INICIO: Código para imprimir el token recibido desde el frontend ---
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
           // String token = authorizationHeader.substring(7); // Extrae solo la parte del token
            //System.out.println("--- TOKEN JWT RECIBIDO EN BACKEND ---");
            //System.out.println("Cabecera Authorization: " + authorizationHeader);
            //System.out.println("Token JWT (extraído): " + token);
            //System.out.println("--- FIN TOKEN JWT RECIBIDO EN BACKEND ---");
        } else {
            //System.out.println("--- TOKEN JWT NO RECIBIDO EN BACKEND ---");
            //System.out.println("Cabecera Authorization ausente o no tiene formato Bearer.");
            //System.out.println("--- FIN TOKEN JWT NO RECIBIDO EN BACKEND ---");
        }
        // --- FIN: Código para imprimir el token ---

        try {
            keycloakUserService.crearUsuario(usuarioRequest);
            Map<String, String> successResponse = Collections.singletonMap("message", "Usuario creado exitosamente");
            
            // --- INICIO: DEPURA LA RESPUESTA JSON SALIENTE (ÉXITO) ---
            try {
                String jsonResponse = objectMapper.writeValueAsString(successResponse);
                System.out.println("************************************************");
                System.out.println("--- RESPUESTA JSON DEL BACKEND (ÉXITO) ---");
                System.out.println(jsonResponse);
                System.out.println("--- FIN RESPUESTA JSON ---");
                System.out.println("************************************************");
            } catch (Exception e) {
                System.err.println("Error al serializar la respuesta JSON de éxito para depuración: " + e.getMessage());
            }
            // --- FIN: DEPURA LA RESPUESTA JSON SALIENTE (ÉXITO) ---

            return ResponseEntity.status(HttpStatus.CREATED)
                    //.body("Usuario creado exitosamente");
                    .body(Collections.singletonMap("message", "Usuario creado exitosamente"));
        } catch (RuntimeException e) {
            Map<String, String> errorResponse = Collections.singletonMap("error", e.getMessage());

            // --- INICIO: DEPURA LA RESPUESTA JSON SALIENTE (ERROR) ---
            try {
                String jsonResponse = objectMapper.writeValueAsString(errorResponse);
                System.out.println("************************************************");
                System.out.println("--- RESPUESTA JSON DEL BACKEND (ERROR) ---");
                System.out.println(jsonResponse);
                System.out.println("--- FIN RESPUESTA JSON ---");
                System.out.println("************************************************");
            } catch (Exception ex) {
                System.err.println("Error al serializar la respuesta JSON de error para depuración: " + ex.getMessage());
            }
            // --- FIN: DEPURA LA RESPUESTA JSON SALIENTE (ERROR) ---
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    //.body(Map.of("error", e.getMessage()));
                    .body(Collections.singletonMap("error", e.getMessage()));
        }
    }

    // Listar usuarios, devuelve lista simple (puedes mejorar el DTO o paginación si quieres)
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')") // <-- ¡AÑADE ESTO AQUÍ!
    public ResponseEntity<List<KeycloakUserResponse>> listarUsuarios(
            @RequestParam(required = false) String username) {
        List<KeycloakUserResponse> usuarios = keycloakUserService.listarUsuarios(username);
        return ResponseEntity.ok(usuarios);
    }
    
    // Asignar rol a usuario específico
    @PostMapping("/{userId}/roles")
    @PreAuthorize("hasRole('ADMIN')") // <-- ¡AÑADE ESTO AQUÍ!
    public ResponseEntity<?> asignarRol(
            @PathVariable String userId,
            @RequestParam String rol) {
        try {
            keycloakUserService.asignarRolAdmin(userId, rol);
            //return ResponseEntity.ok(Map.of("mensaje", "Rol asignado correctamente"));
            return ResponseEntity.ok(Collections.singletonMap("message", "Rol asignado correctamente")); // ¡AJUSTADO: consistent JSON!
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    //.body(Map.of("error", e.getMessage()));
                    .body(Collections.singletonMap("error", e.getMessage()));
        }
    }

    @GetMapping("/all")
    @PreAuthorize("hasRole('ADMIN')") // <-- ¡AÑADE ESTO AQUÍ!
    public ResponseEntity<List<KeycloakUserResponse>> listarUsuariosGen(
            @RequestParam(required = false) String username) {
        if (username == null || username.isEmpty()) {
            List<KeycloakUserResponse> usuarios = keycloakUserService.listarUsuariosGenerico();
            return ResponseEntity.ok(usuarios);
        } else {
            // Aquí tendrías que tener otro método que liste por username, o implementar lógica adicional.
            // Si no tienes ese método, podrías lanzar excepción o retornar vacío.
            return ResponseEntity.ok(List.of()); // vacío por ejemplo
        }
    }

    // Actualizar usuario (nuevo endpoint que integra tu método en el servicio)
    @PutMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')") // <-- ¡AÑADE ESTO AQUÍ!
    public ResponseEntity<?> actualizarUsuario(
            @PathVariable String userId,
            @Valid @RequestBody UsuarioRequest usuarioRequest) {
        try {
            keycloakUserService.actualizarUsuario(userId, usuarioRequest);
            //return ResponseEntity.ok(Map.of("mensaje", "Usuario actualizado correctamente"));
            return ResponseEntity.ok(Collections.singletonMap("message", "Usuario actualizado correctamente")); // ¡AJUSTADO: consistent JSON!
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    //.body(Map.of("error", e.getMessage()));
                    .body(Collections.singletonMap("error", e.getMessage()));
        }
    }

    @GetMapping("/roles") // Endpoint para obtener TODOS los roles del cliente vetcare-app
    @PreAuthorize("hasRole('ADMIN')") // O un rol apropiado que tenga el usuario autenticado
    public Mono<ResponseEntity<List<String>>> listarTodosLosRolesDelClienteKeycloak() {
        System.out.println("--- CONTROLADOR: Solicitando TODOS los roles del CLIENTE Keycloak (Usando WebClient) ---");

        // keycloakAdminClient.getAllRolesForTargetClient() ahora devuelve Mono<List<String>>
        return keycloakAdminClient.getAllRolesForTargetClient()
                .map(roles -> {
                    // Cuando el Mono emita la lista de roles, la envolvemos en un ResponseEntity.ok()
                    //System.out.println("Roles del cliente '" + keycloakProperties.getClientName() + "' obtenidos de Keycloak Admin API: " + roles);
                    return ResponseEntity.ok(roles);
                })
                // Si el Mono de roles está vacío (ej. cliente no encontrado o no tiene roles),
                // devolvemos un ResponseEntity.ok con una lista vacía
                .defaultIfEmpty(ResponseEntity.ok(List.of()))
                // Manejo de errores: Si ocurre una excepción en la cadena reactiva
                .onErrorResume(e -> {
                    //System.err.println("Error en el controlador al obtener roles del cliente: " + e.getMessage());
                    // Devolvemos un Mono que emite un ResponseEntity con un error 500 y un mensaje
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            //.body(List.of("Error al obtener roles: " + e.getMessage())));
                            .body(Collections.singletonList("Error al obtener roles: " + e.getMessage()))); // ¡AJUSTADO: consistent JSON error!
                });
    }

    @DeleteMapping("/delete/{userId}")
    @PreAuthorize("hasRole('ADMIN')") // Solo un admin puede eliminar usuarios
    public ResponseEntity<?> eliminarUsuario(@PathVariable String userId) {
        try {
            keycloakUserService.eliminarUsuario(userId);
            // ¡AJUSTADO: consistent JSON para éxito!
            return ResponseEntity.ok(Collections.singletonMap("message", "Usuario eliminado exitosamente."));
        } catch (RuntimeException e) {
            // ¡AJUSTADO: consistent JSON para error!
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Collections.singletonMap("error", "Error al eliminar usuario: " + e.getMessage()));
        }
    }


     // --- NUEVOS ENDPOINTS PARA BUSCAR USUARIOS POR ROL ---

    /**
     * Endpoint para obtener usuarios por un rol de cliente específico.
     * Requiere el rol 'ADMIN' para acceder.
     * @param roleName El nombre del rol de cliente (ej. "veterinario", "asistente").
     * @return Mono<ResponseEntity<List<Map<String, Object>>>> Una respuesta HTTP con la lista de usuarios.
     */
   // --- NUEVOS ENDPOINTS PARA BUSCAR USUARIOS POR ROL (CORREGIDOS) ---

    @GetMapping("/byClientRole/{roleName}")
    @PreAuthorize("hasRole('ADMIN')")
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
                    // Asegúrate de que el tipo devuelto coincida exactamente
                    // Castear explícitamente para evitar la inferencia genérica amplia
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
    @PreAuthorize("hasRole('ADMIN')")
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
    
}
