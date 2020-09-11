package com.mybarber.servidor_autentificacao.repository;


import com.mybarber.servidor_autentificacao.model.Usuario;

import java.util.Map;

public interface UsuarioDAO {

	Usuario buscarPorLogin(String login);
	Map<String, String> buscarBarbeariaPorLogin(String login);
}
