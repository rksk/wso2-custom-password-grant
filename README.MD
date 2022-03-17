# Custom Password Grant Handler for  [WSO2 Identity Server](https://wso2.com/identity-and-access-management/)

 * This custom password grant handler overrides the default password grant handler to skip the requirement of apending tenant domain to the end of username in multi-tenancy.
 * This uses SP tenant to identify the user tenant.
 * This is not compatible with SaaS service providers since they identify the user tenant from the username itself.

### Steps to deploy
- Build the component by running "mvn clean install".
- Copy `custom-password-grant-1.0.0.jar` file which can be found in target directory into `<IS_HOME>/repository/components/lib' directory.
- Open `repository/conf/identity/identity.xml` file and look for following block.
```dtd
<SupportedGrantType>
    <GrantTypeName>password</GrantTypeName>
    <GrantTypeHandlerImplClass>org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler</GrantTypeHandlerImplClass>
</SupportedGrantType>
```
- Replace the `GrantTypeHandlerImplClass` with our custom class as below.
```dtd
<SupportedGrantType>
    <GrantTypeName>password</GrantTypeName>
    <GrantTypeHandlerImplClass>org.wso2.identity.custom.grant.password.CustomPasswordGrantHandler</GrantTypeHandlerImplClass>
</SupportedGrantType>
```
- Restart the Identity Server.
