package com.github.joeri5.joeridev.session;

import com.github.joeri5.joeridev.user.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity
@Table(name = "sessions")
@Getter
@Setter
@NoArgsConstructor
public class Session {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID uuid;

    private String token;

    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;

    public Session(String token, User user) {
        this.token = token;
        this.user = user;
    }

}