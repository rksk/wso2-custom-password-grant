package org.wso2.identity.custom.grant.password;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;

/**
 * Modified version of password grant type to avoid apending tenant domain to the end of username.
 * This uses SP tenant to identify the user tenant.
 * This is not compatible with SaaS service providers since they identify the user tenant from the username itself.
 */
public class CustomPasswordGrantHandler extends PasswordGrantHandler {

    private static Log log = LogFactory.getLog(CustomPasswordGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        String userFromRequest = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getResourceOwnerUsername();
        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();

        if (log.isDebugEnabled()) {
            log.debug("Username: " + userFromRequest + ", SP tenant domain: " + tenantDomain);
        }
        tokReqMsgCtx.getOauth2AccessTokenReqDTO().setResourceOwnerUsername(userFromRequest + "@" + tenantDomain);

        return super.validateGrant(tokReqMsgCtx);
    }

}
