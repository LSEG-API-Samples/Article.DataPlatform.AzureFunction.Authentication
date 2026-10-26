# Building LSEG Authentication in Power Query Using Azure Functions and Redis

This article demonstrates how to centralize authentication for LSEG Data Platform APIs by using Azure Functions and Azure Cache for Redis. The solution improves security by removing credentials from Power BI reports and improves performance through token caching and controlled token refresh operations.

## Architecture Overview
The following section provides a brief overview of how this solution works.

1. Power BI calls an Azure Function to obtain an access token. The Azure Function authenticates users using basic authentication with a username and password. Upon successful authentication, the Azure Function returns an access token to Power BI.
2. After validating the user credentials, the Azure Function retrieves an access token from Redis. If the token is still valid and has not expired, it is returned to Power BI. Otherwise, the Azure Function connects to the LSEG Data Platform Authentication Service to refresh or obtain a new access token, which is then returned to Power BI.
3. When a token refresh or renewal is required, the Azure Function calls the LSEG Data Platform Authentication Service to obtain a new access token. The new token is then stored in Redis and returned to Power BI for subsequent requests.

This approach improves security and performance by ensuring that no client secrets are stored in Power BI. Credentials are managed centrally, making administration and rotation easier while reducing the risk of exposure. By caching authentication tokens in Azure Redis, the solution minimizes repeated authentication requests to the LSEG Data Platform, reducing authentication traffic and improving efficiency. As a result, Power BI refresh operations can complete faster and more reliably.

__Note:__ The Basic Authentication credentials used to access the Azure Function are independent of the LSEG Data Platform credentials used to obtain OAuth2 access tokens.

For the full article, please visit [this link](https://developers.lseg.com/en/article-catalog/article/building-lseg-authentication-in-power-query-using-azure-function).
