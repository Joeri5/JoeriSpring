package com.github.joeri5.joeridev.auth;

import com.github.joeri5.joeridev.security.jwt.model.AuthRequest;
import com.github.joeri5.joeridev.security.jwt.model.AuthResponse;
import com.github.joeri5.joeridev.session.SessionService;
import com.github.joeri5.joeridev.user.User;
import com.github.joeri5.joeridev.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final SessionService sessionService;
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("login")
    public ResponseEntity<?> onLogin(@RequestBody AuthRequest authRequest) {
        AuthResponse response = userService.loginUser(authenticationManager, authRequest);

        if (response == null) {
            return ResponseEntity.badRequest().build();
        }

        return ResponseEntity.ok(response);
    }

    @PostMapping("register")
    public ResponseEntity<User> onRegister(@RequestBody User user) {
        return new ResponseEntity<>(userService.registerUser(passwordEncoder, user), HttpStatus.CREATED);
    }

    @PostMapping("logout")
    public ResponseEntity<?> onLogout(Authentication authentication) {
        User user = userService.extractFromAuthentication(authentication);
        return ResponseEntity.ok(sessionService.invalidateSessionByUser(user));
    }

}
