package com.krakedev.jwt.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.RequestHeader;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.services.UsuarioService;

import java.util.Map;
import com.krakedev.jwt.utils.JwtUtil;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private final UsuarioService service;

	public AuthController(UsuarioService service) {
		this.service = service;
	}

	@PostMapping("/registrar")
	public ResponseEntity<?> registrar(@RequestBody Usuario usuario) {
		try {
			Usuario usuarioRegistrado = service.registrar(usuario);

			return ResponseEntity.status(HttpStatus.CREATED).body(usuarioRegistrado);

		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("Error al registrar el usuario: " + e.getMessage());
		}
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Usuario usuario) {

		try {

			Usuario usuarioEncontrado = service.login(usuario.getUsername(), usuario.getPassword());

			if (usuarioEncontrado != null) {

				String token = JwtUtil.generarToken(usuarioEncontrado.getUsername(), usuarioEncontrado.getRol());

				return ResponseEntity.ok(Map.of("token", token, "username", usuarioEncontrado.getUsername(), "rol",
						usuarioEncontrado.getRol()));

			} else {

				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciales incorrectas");
			}

		} catch (Exception e) {

			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("Error al iniciar sesión: " + e.getMessage());
		}

	}

	@GetMapping("/perfil")
	public ResponseEntity<?> perfil(
	        @RequestHeader(value = "Authorization", required = false) String authHeader) {

	    if (authHeader == null || !authHeader.startsWith("Bearer ")) {

	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
	                .body("Acceso Denegado: Debes proveer un token Bearer válido en la cabecera Authorization");
	    }

	    String token = authHeader.substring(7);

	    DecodedJWT datosToken = JwtUtil.validarToken(token);

	    if (datosToken == null) {

	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
	                .body("Acceso Denegado: Token Inválido o Expirado");
	    }

	    String usuario = datosToken.getSubject();
	    String rol = datosToken.getClaim("rol").asString();

	    return ResponseEntity.ok(Map.of(
	            "Mensaje", "Bienvenido al sistema protegido por JWT",
	            "Usuario", usuario,
	            "Rol", rol,
	            "Estatus", "Autenticado Exitosamente"
	    ));
	}

}
