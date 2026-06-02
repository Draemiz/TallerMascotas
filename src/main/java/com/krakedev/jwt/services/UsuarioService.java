package com.krakedev.jwt.services;

import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;

@Service
public class UsuarioService {

    private final UsuarioRepository repo;

    public UsuarioService(UsuarioRepository repo) {
        this.repo = repo;
    }

    public Usuario registrar(Usuario usuario) {

        String hash = BCrypt.hashpw(
                usuario.getPassword(),
                BCrypt.gensalt());

        usuario.setPassword(hash);

        return repo.save(usuario);
    }

    public Usuario login(String username, String password) {

        Optional<Usuario> usuario =
                repo.findByUsername(username);

        if (usuario.isPresent()) {

            Usuario u = usuario.get();

            if (BCrypt.checkpw(password, u.getPassword())) {
                return u;
            }
        }

        return null;
    }
}