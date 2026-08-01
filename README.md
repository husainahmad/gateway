# Gateway — POS Harmoni

Single entry point for the POS Harmoni backend. Routes requests from clients to
the downstream microservices (`authentication`, `dashboard-order`, etc.) and
applies cross-cutting concerns (CORS, future auth, future rate limiting) in one
place.

## Stack

- Spring Boot 3.5.11, Java 21
- Spring Cloud Gateway (WebMVC variant) 2025.0.1
- Spring Security + OAuth2 Resource Server (JWT)

## Routes

All paths are prefixed with `/api/v1/`. The gateway strips that prefix before
forwarding, so downstream services receive the un-prefixed path.

| Path             | Downstream          |
|------------------|---------------------|
| `/api/v1/auth/**`| `authentication` (:8081) |
| `/api/v1/user/**`| `authentication` (:8081) |
| `/api/v1/{chain,brand,category,customization,product,service,sku,skutier,store,storeservicetype,subservice,tier}/**` | `dashboard-order` (:8082) |

## Security posture — read this before deploying

**JWT validation is NOT currently enforced.** The `spring.security.oauth2.
resourceserver.jwt.issuer-uri` block is commented out in `application.yml`
because the auth service uses HS256 with a shared HMAC secret and does not
expose a JWKS endpoint — turning validation on as-is would fail at startup.

Practically this means:

- `/api/v1/**` is `permitAll()` at the gateway.
- `SecurityContextHolder.getAuthentication()` is `null` for every request that
  reaches the gateway, because no authentication ever happens here.
- Downstream services are responsible for their own auth (the auth service has
  a custom `JwtFilter`; other services currently do not validate).

This is **not** production-safe. See "Known limitations" below.

## Known limitations / next refactor

1. **JWT validation** — needs an auth-service redesign (RS256 + JWKS endpoint)
   or an out-of-band HMAC secret, before the gateway can enforce tokens.
2. **`X-User` propagation** — depends on (1); downstream services don't
   currently consume an `X-User` header, so this is a new contract.
3. **Role-based authorization** — the auth service issues a `roles` claim but
   does not map it to `GrantedAuthority`. To do per-route authz in the gateway,
   that mapping must be added.
4. **Rate limiting** — Redis was removed (reactive starter, incompatible with
   the WebMVC gateway). If needed, swap in the blocking starter plus bucket4j.
5. **CORS** — the gateway ships a permissive default CORS config. Tighten the
   allowed origins per environment before exposing publicly.

## Running locally

```
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

Then health-check: `curl http://localhost:8080/actuator/health`.