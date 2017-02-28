# Spring boot OAuth2 and LDAP

This repository represents a Spring Boot project demonstrating authentication with OAuth2 (Google/Facebook/Github) along with a configurable LDAP server.

Each of these can be disabed by commenting the relevant properties in `application.properties` (In this repository, facebook is disabled. To enable, uncomment the facebook block)

# Usage

```
gradle build
java -jar build/libs/authenticating-oauth2-0.1.0.jar
```

# Configuring LDAP

You can either use the supporting [ldap server](https://github.com/thatkow/ldap_example_server), or configure application.properties to point to your own.


