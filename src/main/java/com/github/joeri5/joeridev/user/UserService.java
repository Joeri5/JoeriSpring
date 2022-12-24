package com.github.joeri5.joeridev.user;

import com.github.joeri5.joeridev.security.jwt.JwtTokenUtil;
import com.github.joeri5.joeridev.security.jwt.model.AuthRequest;
import com.github.joeri5.joeridev.security.jwt.model.AuthResponse;
import com.github.joeri5.joeridev.session.Session;
import com.github.joeri5.joeridev.session.SessionService;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final SessionService sessionService;

    private final UserRepository userRepository;

    private final JwtTokenUtil jwtTokenUtil;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username);
    }

    public @Nullable User extractFromAuthentication(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()
                || authentication.getPrincipal() == null) {
            return null;
        }

        return (User) authentication.getPrincipal();
    }

    public User registerUser(PasswordEncoder passwordEncoder, User user) {
        String encryptedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encryptedPassword);
        return userRepository.save(user);
    }

    public @Nullable AuthResponse loginUser(AuthenticationManager authenticationManager, AuthRequest authRequest) {
        String email = authRequest.getEmail(), password = authRequest.getPassword();

        boolean success = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(email, password))
                .isAuthenticated();
        if (!success) {
            return null;
        }

        User user = userRepository.findByEmail(email);
        String token = jwtTokenUtil.generateJwt(user);

        Session session = new Session(token, user);
        sessionService.activateSession(session);

        return new AuthResponse(token);
    }

}
