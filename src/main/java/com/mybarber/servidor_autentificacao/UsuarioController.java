package com.mybarber.servidor_autentificacao;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UsuarioController {
    @GetMapping("/user/me")
    public Principal user(Principal principal) {

        return principal;
    }
}
