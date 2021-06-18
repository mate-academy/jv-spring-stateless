# Spring Security. Stateless

1. Implement method `protected void configure(HttpSecurity http)` in the `SecurityConfig` class
1. Permit access for all user to "/register", "/login", "/inject" endpoints
1. Permit access only for ADMIN to all endpoints marked with `@DeleteMapping` annotation
1. Create and implement class `JwtTokenProvider`
1. Create and implement class `JwtTokenFilter`
1. Create and implement class `JwtConfigurer`
1. Implement `"/login"` endpoint
1. Create your own exception `InvalidJwtAuthenticationException`

