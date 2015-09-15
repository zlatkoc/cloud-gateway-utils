Sample Java WEB project for authenticating with Open Saml library with Wagamarket application

Requirements:
 - Java EE Web server (e.g. Tomcat, Glassfish)
 - Maven 3.x

Configuration:

Import public key cerificata into /src/main/resources/keystore.jks, for example:
> cd  /src/main/resources/
> keytool  -keystore keystore.jks -importcert -file ~/Downloads/dev_sso.crt -alias sso-dev

The keystore password is: 'changeit'


Check src/main/resources/config.properties
 - configure SSO endpoint URL and alias with public key cerificate in keystore.jks that was added in previous step
 - import additional certificates if needed

Build:
 mvn install

Deploy:
 copy target/open-saml-sample.war to your application server

Run:
 Open "http://<your-app-server-URL>/open-saml-sample/" ,e.g. http://localhost:8080/open-saml-sample/






