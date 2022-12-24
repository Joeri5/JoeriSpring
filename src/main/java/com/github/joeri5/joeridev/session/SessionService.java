package com.github.joeri5.joeridev.session;

import com.github.joeri5.joeridev.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SessionService {

    private final SessionRepository sessionRepository;

    public void activateSession(Session session) {
        Session activeSession = sessionRepository.findByUser(session.getUser());
        if (activeSession != null) {
            this.invalidateSession(activeSession);
        }

        sessionRepository.save(session);
    }

    public void invalidateSession(Session session) {
        sessionRepository.delete(session);
    }

    public boolean invalidateSessionByToken(String token) {
        Session session = sessionRepository.findByToken(token);
        if (session != null) {
            this.invalidateSession(session);
        }
        return session != null;
    }

    public boolean invalidateSessionByUser(User user) {
        Session session = sessionRepository.findByUser(user);
        if (session != null) {
            this.invalidateSession(session);
        }
        return session != null;
    }

    public boolean isSessionActive(String token) {
        return sessionRepository.findByToken(token) != null;
    }

}