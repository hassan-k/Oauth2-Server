
# Oauth2 security for Microservices

OAuth 2 is an authorization framework that enables applications to obtain limited access to user accounts on an HTTP service, such as Facebook, GitHub, and DigitalOcean.

![alt text](https://raw.githubusercontent.com/hassan-k/Oauth2-Server/master/SM3.png)



## Roles

OAuth2 defines 4 roles 

�	Resource Owner(a.k.a. the User): An entity capable of granting access to a protected resource. When the resource owner is a person, it is referred to as an end-user

�	Resource Server(a.k.a. the API server): The server hosting the protected resources, capable of accepting and responding to protected resource requests using access tokens.

�	Client: application requesting access to a resource server (it can be your PHP website, a Javascript application or a mobile application).

�	Authorization Server: The server issuing access tokens to the client after successfully authenticating the resource owner and obtaining authorization. This token will be used for the client to request the resource server. This server can be the same as the authorization server (same physical server and same application), and it is often the case.


## Tokens

Tokens are random strings generated by the authorization server and are issued when the client requests them.
There are 2 types of token:

�	Access Token: this is the most important because it allows the user data from being accessed by a third-party application. This token is sent by the client as a parameter or as a header in the request to the resource server. It has a limited lifetime, which is defined by the authorization server. 

�	Refresh Token: this token is issued with the access token but unlike the latter, it is not sent in each request from the client to the resource server. It merely serves to be sent to the authorization server for renewing the access token when it has expired.
Authorization Grant Types


The OAuth 2.0 specification is a flexibile authorization framework that describes a number of grants (�methods�) for a client application to acquire an access token (which represents a user�s permission for the client to access their data) which can be used to authenticate a request to an API endpoint.

The specification describes five grants for acquiring an access token:

�	Authorization code grant

�	Implicit grant

�	Resource owner credentials grant

�	Client credentials grant

�	Refresh token grant

I have used "Resource owner credentials grant" in Oauth server implementation as a authorization grant type.


## Endpoints and their purpose

The endpoints that we need to reach to get token and use it to get to the resources. we can check this endpoints via postman.

? Attempt to access resources [REST API] without any authorization [will fail ofcourse]. For example:http://localhost:9001/api/users

? Ask for tokens[access+refresh] using HTTP POST on /oauth/token , with grant_type=password, and resource owners credentials as reqparams.

Additionally, send client credentials in Authorization header. For example:http://localhost:9001/oauth/token?grant_type=password&username=foo&password=pss

? Ask for a new access token via valid refreshtoken, using HTTP POST on /oauth/token, with grant_type=refresh_token,and sending actual refresh token.

Additionally, send client credentials in Authorization header. For example:

http://localhost:9001/oauth/token?grant_type=refresh_token&refresh_token=094b7d23973f4cc183ad8ffd43de1845

? Access the resource by providing an access token using access_token query param with request. For example:

http://localhost:9001/api/users/?access_token=3525d0e4d88149e79f91bcfd18259109

## How to Run
Do the following steps:
- Add your LDAP server information in application.yml file.
- Create a keypack.jks and replace the existing one in resourses folder.
- Add keypack password in application.yml
- Add a password for Basic Auth in application.yml
- Run the project

