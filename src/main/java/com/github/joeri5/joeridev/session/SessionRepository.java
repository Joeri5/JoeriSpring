package com.github.joeri5.joeridev.session;

import com.github.joeri5.joeridev.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface SessionRepository extends JpaRepository<Session, UUID> {

    Session findByUser(User user);
    Session findByToken(String token);

}