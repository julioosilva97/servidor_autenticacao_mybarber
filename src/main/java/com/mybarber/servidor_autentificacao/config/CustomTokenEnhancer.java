package com.mybarber.servidor_autentificacao.config;

import com.mybarber.servidor_autentificacao.repository.UsuarioDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class CustomTokenEnhancer implements TokenEnhancer {

    @Autowired
    private UsuarioDAO usuarioDAO;

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        
        if (authentication.getOAuth2Request().getGrantType().equalsIgnoreCase("password")) {
            final Map<String, Object> additionalInfo = new HashMap<String, Object>();

            var dadosUsuario = usuarioDAO.buscarBarbeariaPorLogin(authentication.getName());

            if (dadosUsuario != null) {
                additionalInfo.put("dadosUsuario", dadosUsuario);
            } else {
                additionalInfo.put("dadosUsuario", "Erro ao buscar dados");
            }

            ((DefaultOAuth2AccessToken) accessToken)
                    .setAdditionalInformation(additionalInfo);
        }

        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(new HashMap<>());
        accessToken = enhance(accessToken, authentication);
        return accessToken;
    }

}
