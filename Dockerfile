# Etapa 1: Construcción con Maven y JDK 17
FROM maven:3.9.6-eclipse-temurin-17 AS buildstage

WORKDIR /app

# Copiar archivos necesarios
COPY pom.xml .
COPY src /app/src

# --- Líneas eliminadas: NO COPIAR WALLET NI CONFIGURAR TNS_ADMIN ---
# COPY src/wallet /app/wallet
# ENV TNS_ADMIN=/app/wallet
# ------------------------------------------------------------------

# Compilar la aplicación sin ejecutar los tests
RUN mvn clean package -DskipTests

# Etapa 2: Imagen de ejecución con solo JDK 17
FROM eclipse-temurin:17-jdk

WORKDIR /app

# Copiar el JAR generado desde la etapa de build
COPY --from=buildstage /app/target/*.jar /app/app.jar

# --- Líneas eliminadas: NO COPIAR WALLET NI CONFIGURAR TNS_ADMIN ---
# COPY src/wallet /app/wallet
# ENV TNS_ADMIN=/app/wallet
# ------------------------------------------------------------------

# Puerto que expone tu aplicación (¡IMPORTANTE: este puerto puede ser diferente para este microservicio!)
EXPOSE 8081 

# Comando de inicio
ENTRYPOINT ["java", "-jar", "/app/app.jar"]