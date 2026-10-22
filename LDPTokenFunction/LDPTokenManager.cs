using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Text;

namespace LDPTokenFunction
{
    public class LDPTokenManager
    {
        private readonly ILogger _logger;
        private ITokenManager _tokenManager;
        public LDPTokenManager(ILoggerFactory loggerFactory, ITokenManager tokenManager)
        {
            _logger = loggerFactory.CreateLogger<LDPTokenManager>();
            _tokenManager = tokenManager;
        }

        [Function("Token")]
        public async Task<HttpResponseData> GetToken([HttpTrigger(AuthorizationLevel.Function, "get", "delete")] HttpRequestData req)
        {
            _logger.LogInformation("C# GetToken HTTP trigger function processed a request.");

            if (CheckBasicAuth(req) == false)
            {
                return CreateUnauthorizedResponse(req, "Basic Authenitcation Failed");
            }
            try
            {
                if (req.Method == "DELETE")
                {
                    return await DeleteToken(req);
                }
                else
                {
                    
                    var tokenInfo = _tokenManager.GetToken();
                    if (tokenInfo == null)
                    {
                        var response = req.CreateResponse(HttpStatusCode.Unauthorized);
                        response.Headers.Add("Content-Type", "text/plain; charset=utf-8");
                        response.WriteString("No valid token available. Please set credentials first.");
                        return await Task.FromResult(response);
                    }
                    var jsonResponse = System.Text.Json.JsonSerializer.Serialize(tokenInfo);
                    var successResponse = req.CreateResponse(HttpStatusCode.OK);
                    //successResponse.Headers.Add("Content-Type", "application/json; charset=utf-8");
                    await successResponse.WriteAsJsonAsync(tokenInfo);
                    return await Task.FromResult(successResponse);
                }
            }
            catch (Exception ex)
            {
                var response = req.CreateResponse(HttpStatusCode.Unauthorized);
                response.Headers.Add("Content-Type", "text/plain; charset=utf-8");
                response.WriteString(ex.Message);
                return await Task.FromResult(response);
            }
        }

     
        public async Task<HttpResponseData> DeleteToken([HttpTrigger(AuthorizationLevel.Function, "delete")] HttpRequestData req)
        {
            _logger.LogInformation("C# DeleteToken HTTP trigger function processed a request.");
            _tokenManager.DeleteToken();
            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/plain; charset=utf-8");
            response.WriteString("Token deleted.");
            return await Task.FromResult(response); 
        }

        //[Function("SetBasicAuthen")]
        //public async Task<HttpResponseData> SetBasicAuthen([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
        //{
        //    _logger.LogInformation("C# SetBasicAuthen HTTP trigger function processed a request.");

        //    if (CheckBasicAuth(req) == false)
        //    {
        //        return CreateUnauthorizedResponse(req, "Basic Authenitcation Failed");
        //    }

        //    var credentials = await req.ReadFromJsonAsync<BasicAuthCredentials>();
        //    if(credentials == null)
        //    {
        //        var response1 = req.CreateResponse(HttpStatusCode.BadRequest);
        //        response1.Headers.Add("Content-Type", "text/plain; charset=utf-8");
        //        response1.WriteString("Invalid request body. Please provide valid credentials.");
        //        return response1;
        //    }
        //    _tokenManager.SetBasicAuthen(credentials.Username, credentials.Password);
        //    var response = req.CreateResponse(HttpStatusCode.OK);
        //    response.Headers.Add("Content-Type", "text/plain; charset=utf-8");
        //    response.WriteString("Basic authentication credentials set.");
        //    return response;
        //}
        private HttpResponseData CreateUnauthorizedResponse(HttpRequestData req, string message)
        {
            var response = req.CreateResponse(HttpStatusCode.Unauthorized);

            // Force browser or client tool to recognize Basic Auth challenge
            response.Headers.Add("WWW-Authenticate", "Basic realm=\"AzureFunction\"");
            response.WriteStringAsync(message).Wait();

            return response;
        }

        //[Function("SetCredentials")]
        //public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
        //{
        //    _logger.LogInformation("C# SetCredentials HTTP trigger function processed a request.");

        //    if(CheckBasicAuth(req) == false)
        //    {
        //        return CreateUnauthorizedResponse(req, "Basic Authenitcation Failed");
        //    }

        //    var credentials = await req.ReadFromJsonAsync<LSEGCredentials>();

        //    if(credentials != null)
        //        _tokenManager.SetCredentials(credentials.Username, credentials.Password, credentials.ClientId);

        //    var response = req.CreateResponse(HttpStatusCode.OK);
        //    response.Headers.Add("Content-Type", "text/plain; charset=utf-8");

        //    response.WriteString("Credentials set.");

        //    return response;
        //}

        private bool CheckBasicAuth(HttpRequestData req)
        {
            if (!req.Headers.TryGetValues("Authorization", out var authHeaders))
            {
                return false;
            }
            var authHeader = authHeaders.FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            var encodedCredentials = authHeader.Substring("Basic ".Length).Trim();
            var decodedBytes = Convert.FromBase64String(encodedCredentials);
            var decodedCredentials = Encoding.UTF8.GetString(decodedBytes);
            var parts = decodedCredentials.Split(':', 2);
            if (parts.Length != 2)
            {
                return false;
            }
            var username = parts[0];
            var password = parts[1];
            return _tokenManager.ValidateUser(username, password);
        }
    }
}
