# Etapa 1: Build con Maven y Java 17
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src /app/src
RUN mvn clean package -DskipTests

# Etapa 2: Imagen de ejecución con JDK 17
FROM eclipse-temurin:17-jdk
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

# Exponer el puerto en que tu app escucha
EXPOSE 8081

ENTRYPOINT ["java", "-jar", "app.jar"]
# docker build -t keycloak_admin_cli .
# docker run -d -p 8081:8081 --name keycloak_admin_cli_app --restart unless-stopped keycloak_admin_cli
