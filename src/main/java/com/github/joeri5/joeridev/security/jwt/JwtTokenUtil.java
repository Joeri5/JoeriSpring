package com.github.joeri5.joeridev.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.joeri5.joeridev.user.User;
import com.github.joeri5.joeridev.user.UserRepository;
import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtTokenUtil {

    public static final long JWT_TOKEN_VALIDITY = 3600 * 24 * 7;
    public static final long JWT_TOKEN_REFRESH_AFTER = 3600L;
    @Value("${jwt.secret}")
    private String secret;

    private final UserRepository userRepository;

    /**
     * Generates a JWT token for the given user
     *
     * @param token The token to check
     * @return Whether the token is eligible for a refresh or not
     */
    public boolean eligibleForRefresh(String token) {
        DecodedJWT decodedJWT = verifyJwt(token);
        if (decodedJWT == null) return false;

        return new Date().getTime() > decodedJWT.getIssuedAt().getTime() +
                (JWT_TOKEN_REFRESH_AFTER * 1000L);
    }


    /**
     * Generates a JWT token for the given {@see User}
     * @param user The user to generate the token for
     * @return The generated JWT token
     */
    public String generateJwt(User user) {
        JWTCreator.Builder jwtBuilder = JWT.create();
        jwtBuilder.withSubject(user.getUsername());
        jwtBuilder.withIssuedAt(new Date());
        jwtBuilder.withExpiresAt(new Date(System.currentTimeMillis()
                + JWT_TOKEN_VALIDITY * 1000));
        jwtBuilder.withIssuer("jobboard");

        return jwtBuilder.sign(Algorithm.HMAC512(secret.getBytes()));
    }

    /**
     * Verifies a JWT token and returns the decoded token
     * @param token The token to verify
     * @return The decoded token
     */
    public @Nullable DecodedJWT verifyJwt(String token) {
        return JWT.require(Algorithm.HMAC512(this.secret.getBytes()))
                .build()
                .verify(token);
    }

    /**
     * Checks if a JWT token is expired
     * @param token The token to check
     * @return True if the token is expired or is invalid, false otherwise
     */
    public boolean isTokenExpired(String token) {
        DecodedJWT decodedJWT = verifyJwt(token);
        if (decodedJWT == null) {
            return true;
        }

        return decodedJWT.getExpiresAt().before(new Date());
    }

    /**
     * Retrieves the {@see User} from the given JWT token
     * @param token The token to retrieve the user from
     * @return The user from the token or null if token is invalid.
     */
    public @Nullable User getUserFromToken(String token) {
        DecodedJWT decodedJWT = verifyJwt(token);
        if (decodedJWT == null) {
            return null;
        }

        return userRepository.findByEmail(decodedJWT.getSubject());
    }

}