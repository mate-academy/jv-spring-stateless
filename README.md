# Spring Security. Stateless

1. Implement method `protected void configure(HttpSecurity http)` in the `SecurityConfig` class
2. Permit access for all user to `/register`, `/login`, `/inject` endpoints
3. Permit access only for ADMIN to all endpoints marked with `@DeleteMapping` annotation
4. Create and implement class `JwtTokenProvider`
5. Create and implement class `JwtTokenFilter`
6. Create and implement class `JwtConfigurer`
7. Implement `"/login"` endpoint
8. Create your own exception `InvalidJwtAuthenticationException`
