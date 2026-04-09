package com.example.demo.controller;

import com.example.demo.security.AppUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final SecurityContextRepository securityContextRepository;
    private final AppUserService userService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(
            SecurityContextRepository securityContextRepository,
            AppUserService userService,
            PasswordEncoder passwordEncoder
    ) {
        this.securityContextRepository = securityContextRepository;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, String> register(
            @RequestBody AuthRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) {
        userService.registerUser(request.username(), request.password(), request.email());
        return completeLogin(request, httpRequest, httpResponse);
    }

    @PostMapping("/login")
    public Map<String, String> login(
            @RequestBody AuthRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) {
        return completeLogin(request, httpRequest, httpResponse);
    }

    private Map<String, String> completeLogin(
            AuthRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) {
        if (request == null || request.username() == null || request.password() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Thieu username hoac password");
        }

        String username = request.username().trim();
        log.info("Auth attempt for user: {}", username);

        UserDetails userDetails;
        try {
            userDetails = userService.loadUserByUsername(username);
        } catch (Exception ex) {
            log.error("User lookup failed for '{}': {}", username, ex.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Sai ten dang nhap hoac mat khau");
        }

        if (!passwordEncoder.matches(request.password(), userDetails.getPassword())) {
            log.error("Password mismatch for user '{}'", username);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Sai ten dang nhap hoac mat khau");
        }

        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                userDetails,
                null,
                userDetails.getAuthorities()
        );

        httpRequest.getSession(true);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, httpRequest, httpResponse);

        writeInfoCookies(httpRequest, httpResponse, authentication);

        log.info("Auth success for user: {}", username);
        return Map.of(
                "username", userDetails.getUsername(),
                "role", extractRole(authentication)
        );
    }

    private void writeInfoCookies(
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse,
            Authentication authentication
    ) {
        String username = authentication.getName();
        String role = extractRole(authentication);
        Duration maxAge = resolveCookieMaxAge();
        String sameSite = resolveCookieSameSite();
        boolean secure = resolveSecure(httpRequest, sameSite);

        ResponseCookie usernameCookie = ResponseCookie.from("demo_username", username)
                .httpOnly(false)
                .secure(secure)
                .path("/")
                .maxAge(maxAge)
                .sameSite(sameSite)
                .build();

        ResponseCookie roleCookie = ResponseCookie.from("demo_role", role)
                .httpOnly(false)
                .secure(secure)
                .path("/")
                .maxAge(maxAge)
                .sameSite(sameSite)
                .build();

        httpResponse.addHeader("Set-Cookie", usernameCookie.toString());
        httpResponse.addHeader("Set-Cookie", roleCookie.toString());
    }

    private Duration resolveCookieMaxAge() {
        String raw = System.getenv("COOKIE_MAX_AGE_DAYS");
        if (raw == null || raw.isBlank()) {
            return Duration.ofDays(7);
        }
        try {
            return Duration.ofDays(Math.max(Long.parseLong(raw.trim()), 1));
        } catch (NumberFormatException ex) {
            return Duration.ofDays(7);
        }
    }

    private String resolveCookieSameSite() {
        String raw = System.getenv("COOKIE_SAMESITE");
        if (raw != null && !raw.isBlank()) {
            return raw.trim();
        }
        return "Lax";
    }

    private boolean resolveSecure(HttpServletRequest request, String sameSite) {
        String raw = System.getenv("COOKIE_SECURE");
        if (raw != null && !raw.isBlank()) {
            return Boolean.parseBoolean(raw.trim());
        }
        if ("None".equalsIgnoreCase(sameSite)) {
            return true;
        }
        return request.isSecure();
    }

    private String extractRole(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .map(authority -> authority.substring("ROLE_".length()))
                .findFirst()
                .orElse("USER");
    }
}
