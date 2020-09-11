package com.mybarber.servidor_autentificacao.repository;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.mybarber.servidor_autentificacao.model.Perfil;
import com.mybarber.servidor_autentificacao.model.Usuario;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Repository;


@Repository
public class UsuarioDAOImpl implements UsuarioDAO {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public Usuario buscarPorLogin(String login) {

        var buscarPorLogin = """
                		select u.id, u.login, u.senha, u.ativo,
                		p.id id_perfil,p.descricao descricao_perfil from usuario u
                		inner join usuario_perfil up on up.id_usuario = u.id
                		inner join perfil p on up.id_perfil = p.id
                		where login = ?
                """;

        var usuarios = jdbcTemplate.query(buscarPorLogin, new Object[]{login},
                (rs, rowNum) -> new Usuario(rs.getInt("id"),
                        rs.getString("login"),
                        rs.getString("senha"),
                        rs.getBoolean("ativo"),
                        new Perfil(rs.getInt("id_perfil"), rs.getString("descricao_perfil"))
                ));




        if (!usuarios.isEmpty()) {
            var usuario = usuarios.get(0);
            usuario.setPermissoes(buscarPermissoes(usuario.getPerfil()));

            return usuario;
        } else {
            return null;
        }
    }

    @Override
    public Map<String, String> buscarBarbeariaPorLogin(String login) {

        var buscarBarbeariaPorLogin = """
                select b.id id_barbearia, b.descricao descricao_barbearia
                ,CASE WHEN @u.id<>1 THEN 'nao' ELSE 'sim' END as teste,
                CASE WHEN @f.id is not null THEN f.id ELSE null END as id_funcionario,
                CASE WHEN @f.id is not null THEN f.nome ELSE null END as nome_funcionario,
                CASE WHEN @c.id is not null THEN c.id ELSE null END as id_cliente,
                CASE WHEN @c.id is not null THEN c.nome ELSE null END as nome_cliente
                from usuario u
                inner join funcionario f on f.id_usuario = u.id
                inner join barbearia b on f.id_barbearia = b.id
                left join cliente c on c.id_usuario = u.id
                where u.login =  ?              
                """;

        return jdbcTemplate.queryForObject(buscarBarbeariaPorLogin, new Object[]{login},
                (rs, rowNum) -> {
                    HashMap<String, String> results = new HashMap<>();

                    var idFuncioanario = rs.getObject("id_funcionario");
                    if (idFuncioanario != null) {
                        results.put("idBarbearia", rs.getString("id_barbearia"));
                        results.put("nomeBarbearia", rs.getString("descricao_barbearia"));
                        results.put("idFuncionario", idFuncioanario.toString());
                        results.put("nomeFuncionario", rs.getString("nome_funcionario"));
                        return results;
                    } else if (rs.getObject("id_cliente") != null) {
                        results.put("idCliente", rs.getString("id_cliente"));
                        results.put("nomeFuncionario", "nome_cliente");
                        return results;
                    } else {
                        return null;
                    }
                }
        );
    }


    private Collection<GrantedAuthority> buscarPermissoes(Perfil perfil) {

        var buscarPorPerfil = """
                select p.descricao from permissao p
                inner join perfil_permissao pp on pp.id_permissao = p.id
                inner join perfil per on pp.id_perfil = per.id
                where per.id = ?
                """;

        Collection<GrantedAuthority> permissoes = new ArrayList<>();

        var result = jdbcTemplate.query(buscarPorPerfil,
                new Object[]{perfil.getId()},
                (rs, rowNum) -> new SimpleGrantedAuthority("ROLE_" + rs.getString("descricao")));

        result.forEach(r -> permissoes.add(r));

        return permissoes;
    }
}
