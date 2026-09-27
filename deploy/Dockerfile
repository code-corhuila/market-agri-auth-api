# Build context: the repository root (see deploy/compose.yml).

# ─── Build ───────────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src

COPY pom.xml .
COPY auth-core auth-core
COPY auth-adapters auth-adapters
COPY auth-app auth-app

# Tests run in ci.yml; the image only packages. The cache mount keeps ~/.m2 between builds.
RUN --mount=type=cache,target=/root/.m2 mvn -B -q -DskipTests package

# ─── Runtime ─────────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

RUN addgroup -S app && adduser -S app -G app
COPY --from=build /src/auth-app/target/auth-app-*.jar /app/app.jar
USER app

EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
