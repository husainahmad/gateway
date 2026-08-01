# Gateway Service

This project is a Spring Boot gateway service used by a POS platform.

## Tech Stack

- Java 21
- Spring Boot
- MyBatis
- MySQL
- Redis
- JWT
- Maven

## Coding Rules

Always understand the existing architecture before making changes.

Never rewrite an entire class when only a small modification is needed.

Prefer modifying existing code over creating duplicate implementations.

Always preserve backward compatibility.

Never remove existing APIs without explicit instruction.

Use constructor injection only.

Never use field injection.

Use Lombok where appropriate.

Follow existing package naming conventions.

Never introduce unnecessary libraries.

Keep methods small and readable.

When modifying business logic, update unit tests.

If database schema changes are required,
generate SQL migration scripts.

Always run:

mvn test

before finishing a task.