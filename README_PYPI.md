# Wristband Multi-Tenant Authentication SDK for Python FastAPI

Wristband provides enterprise-ready auth that is secure by default, truly multi-tenant, and ungated for small businesses.

- Website: [Wristband Website](https://wristband.dev)
- Documentation: [Wristband Docs](https://docs.wristband.dev/)

For detailed setup instructions and usage guidelines, visit the project's GitHub repository.

- [FastAPI Auth SDK - GitHub](https://github.com/wristband-dev/fastapi-auth)


## Details

This SDK facilitates seamless interaction with Wristband for user authentication within multi-tenant FastAPI applications. It follows OAuth 2.1 and OpenID standards and is supported for Python 3.11+. Key functionalities encompass the following:

- Initiating a login request by redirecting to Wristband.
- Receiving callback requests from Wristband to complete a login request.
- Retrieving all necessary JWT tokens and userinfo to start an application session.
- Logging out a user from the application by revoking refresh tokens and redirecting to Wristband.
- Checking for expired access tokens and refreshing them automatically, if necessary.

You can learn more about how authentication works in Wristband in our documentation:

- [Backend Server Auth Integration](https://docs.wristband.dev/docs/backend-server-integration)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.
