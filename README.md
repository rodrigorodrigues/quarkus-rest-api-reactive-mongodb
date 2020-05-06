# Quarkus RestApi with Reactive Mongodb

This repository contains an example of Quarkus framework with `Restful API + Reactive Programming + JWT + MongoDB`.

## Requirements

To compile and run this project you will need:

- JDK 8+
- Mongodb
- Maven 3.6.3
- Public Key(or use `auth` profile to generate one automatic)

## Install

```
mvn clean install
```

## Run with dev profile

You will need to place a public key in `src/main/resources/META-INF/resources/publicKey.pem`.

```
mvn compile quarkus:dev
```

## Run with auth profile

To generate a private/public key to be able to call the API.

```
QUARKUS_PROFILE=auth mvn compile quarkus:dev
```

## Swagger UI

To access [Swagger UI](http://localhost:8080/swagger-ui) and generate a valid JWT use `/api/auth` when `auth profile` is on.

Use following roles:
- ROLE_ADMIN - Access for all endpoints
- ROLE_COMPANY_READ - Read Access to `GET - /api/companies` and `GET - /api/companies/{id}`.
- ROLE_COMPANY_CREATE - Create Access to `POST - /api/companies`
- ROLE_COMPANY_SAVE - Update Access to `PUT - /api/companies`
- ROLE_COMPANY_DELETE - Delete Access to `DELETE - /api/companies`

PS: To generate a JWT first need to `Logout` on Authorize Button.

## Docker Image

To generate a docker image native.

```
mvn package -Pnative -Dquarkus.native.container-build=true
```

## Configuration

To change default configuration update file [application.properties](src/main/resources/application.properties).

## References

https://www.novixys.com/blog/how-to-generate-rsa-keys-java/

https://quarkus.io/guides/security-jwt#generating-a-jwt

https://quarkus.io/guides/mongodb-panache