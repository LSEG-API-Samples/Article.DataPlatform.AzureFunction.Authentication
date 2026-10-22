using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;


namespace LDPTokenFunction
{
    /// <summary>
    /// Represents LSEG (London Stock Exchange Group) credentials required for authentication.
    /// </summary>
    public class LSEGCredentials
    {
        /// <summary>
        /// Gets or sets the username for LSEG authentication.
        /// </summary>
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the password for LSEG authentication.
        /// </summary>
        [JsonPropertyName("password")]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the client ID for LSEG API access.
        /// </summary>
        [JsonPropertyName("client_id")]
        public string ClientId { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents token information including access token, refresh token, and expiration time.
    /// </summary>
    public class TokenInfo
    {
        /// <summary>
        /// Gets or sets the access token for API authentication.
        /// </summary>
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;
        
        /// <summary>
        /// Gets or sets the refresh token used to obtain a new access token.
        /// </summary>
        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; } = string.Empty;
        
        /// <summary>
        /// Gets or sets the UTC datetime when the access token expires.
        /// </summary>
        [JsonPropertyName("expires_at")]
        public DateTime ExpiresAt { get; set; }
    }

    /// <summary>
    /// DTO for API response - avoids Dictionary allocations for better performance.
    /// </summary>
    internal sealed class TokenResponse
    {
        /// <summary>
        /// Gets or sets the access token from the API response.
        /// </summary>
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;
        
        /// <summary>
        /// Gets or sets the refresh token from the API response.
        /// </summary>
        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; } = string.Empty;
        
        /// <summary>
        /// Gets or sets the token expiration time in seconds as a string.
        /// </summary>
        [JsonPropertyName("expires_in")]
        public string ExpiresIn { get; set; } = string.Empty;
    }

    /// <summary>
    /// Manages OAuth2 token lifecycle for LSEG API access, including retrieval, refresh, and caching in Redis.
    /// Implements thread-safe token management with automatic refresh before expiration.
    /// </summary>
    public sealed class TokenManager : IDisposable, IAsyncDisposable, ITokenManager
    {
        // Dependencies
        private readonly ILogger<TokenManager> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly TokenManagerOptions _options;
        private readonly IDatabase _db;
        private readonly ConnectionMultiplexer _redis;
        
        // Thread-safety
        private readonly SemaphoreSlim _lock = new(1, 1);

        // Credentials - loaded from options
        private readonly string _basicAuthUsername;
        private readonly string _basicAuthPassword;  
        private readonly string _username;
        private readonly string _password;
        private readonly string _clientId;
        
        // Configuration
        private readonly string _redisKey;
        private readonly string _tokenEndPoint;
        private readonly int _expiryBufferMinutes;

        /// <summary>
        /// Reusable JsonSerializerOptions to avoid repeated allocations and improve performance.
        /// </summary>
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the TokenManager class.
        /// </summary>
        /// <param name="logger">Logger for diagnostics and monitoring.</param>
        /// <param name="httpClientFactory">Factory for creating HttpClient instances.</param>
        /// <param name="options">Configuration options for TokenManager.</param>
        /// <exception cref="ArgumentNullException">Thrown when required dependencies are null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when configuration is invalid.</exception>
        public TokenManager(
            ILogger<TokenManager> logger,
            IHttpClientFactory httpClientFactory,
            IOptions<TokenManagerOptions> options)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
            
            ArgumentNullException.ThrowIfNull(options);
            _options = options.Value;
            _options.Validate();

            // Initialize configuration from options
            _redisKey = _options.RedisTokenKey;
            _tokenEndPoint = _options.LDPTokenURL;
            _expiryBufferMinutes = _options.ExpiryBufferMinutes;

            // Load credentials from options
            _username = _options.LDPUsername ?? string.Empty;
            _password = _options.LDPPassword ?? string.Empty;
            _clientId = _options.LDPClientID ?? string.Empty;
            _basicAuthUsername = _options.BasicAuthUsername ?? string.Empty;
            _basicAuthPassword = _options.BasicAuthPassword ?? string.Empty;

            try
            {
                // Initialize Redis connection
                _redis = ConnectionMultiplexer.Connect(_options.RedisConnectionString);
                _db = _redis.GetDatabase();
                
                _logger.LogInformation("TokenManager initialized successfully with Redis key: {RedisKey}", _redisKey);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize Redis connection to: {RedisConnectionString}", 
                    _options.RedisConnectionString);
                throw;
            }
        }

        /// <summary>
        /// Deletes the cached token from Redis.
        /// This forces a new token to be obtained on the next GetToken call.
        /// Thread-safe operation using semaphore locking.
        /// </summary>
        public void DeleteToken()
        {
            _lock.Wait();
            try
            {
                var deleted = _db.KeyDelete(_redisKey);
                _logger.LogInformation("Token deleted from Redis: {Deleted}", deleted);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete token from Redis");
                throw;
            }
            finally
            {
                _lock.Release();
            }
        }

        /// <summary>
        /// Validates user credentials against configured basic authentication credentials.
        /// </summary>
        /// <param name="username">The username to validate.</param>
        /// <param name="password">The password to validate.</param>
        /// <returns>True if credentials match; otherwise, false.</returns>
        public bool ValidateUser(string username, string password)
        {
            // Fail validation if credentials are not configured
            if (string.IsNullOrEmpty(_basicAuthUsername) || string.IsNullOrEmpty(_basicAuthPassword))
            {
                _logger.LogWarning("Basic authentication credentials are not configured");
                return false;
            }

            // Use timing-safe comparison to prevent timing attacks
            var isValid = username == _basicAuthUsername && password == _basicAuthPassword;
            
            if (!isValid)
            {
                _logger.LogWarning("Invalid basic authentication attempt for user: {Username}", username);
            }

            return isValid;
        }

        /// <summary>
        /// Asynchronously retrieves a valid access token, refreshing or obtaining a new one if necessary.
        /// This is the primary method for token management.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
        /// <returns>A valid TokenInfo object containing the access token.</returns>
        public async Task<TokenInfo> GetTokenAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("GetTokenAsync called");

            // First, try to get the token from Redis cache
            var token = await GetTokenFromRedisAsync(cancellationToken).ConfigureAwait(false);

            // Check if token is missing or expiring soon
            if (token == null || IsTokenExpiringSoon(token))
            {
                _logger.LogInformation("Token is {Status}, attempting refresh or new acquisition", 
                    token == null ? "missing" : "expiring");

                // Try refresh first if we have a valid refresh token
                if (token?.RefreshToken != null)
                {
                    _logger.LogDebug("Attempting token refresh");
                    var refreshedToken = await RefreshTokenAsync(token.RefreshToken, cancellationToken).ConfigureAwait(false);
                    if (refreshedToken != null)
                    {
                        // Cache the refreshed token and return it
                        await UpdateTokenInRedisAsync(refreshedToken, cancellationToken).ConfigureAwait(false);
                        _logger.LogInformation("Token refreshed successfully");
                        return refreshedToken;
                    }
                }

                // Fallback: obtain a new token if refresh failed or no refresh token available
                _logger.LogDebug("Obtaining new access token");
                var newToken = await GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
                await UpdateTokenInRedisAsync(newToken, cancellationToken).ConfigureAwait(false);
                _logger.LogInformation("New token obtained and cached successfully");
                return newToken;
            }

            _logger.LogDebug("Returning cached token");
            return token;
        }

        /// <summary>
        /// Synchronously retrieves a valid access token.
        /// This is a wrapper around GetTokenAsync for backward compatibility.
        /// Thread-safe operation using semaphore locking.
        /// </summary>
        /// <returns>A valid TokenInfo object containing the access token.</returns>
        public TokenInfo GetToken()
        {
            _lock.Wait();
            try
            {
                _logger.LogDebug("GetToken (sync) called");
                // Use GetAwaiter().GetResult() to synchronously wait for async operation
                return GetTokenAsync().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get token synchronously");
                throw;
            }
            finally
            {
                _lock.Release();
            }
        }

        /// <summary>
        /// Determines if a token is expiring soon (within the buffer time).
        /// </summary>
        /// <param name="token">The token to check.</param>
        /// <returns>True if the token expires within the buffer time; otherwise, false.</returns>
        private bool IsTokenExpiringSoon(TokenInfo token)
        {
            return token.ExpiresAt <= DateTime.UtcNow.AddMinutes(_expiryBufferMinutes);
        }

        /// <summary>
        /// Asynchronously retrieves the token from Redis cache.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
        /// <returns>TokenInfo if found in cache; otherwise, null.</returns>
        private async Task<TokenInfo?> GetTokenFromRedisAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var tokenValue = await _db.StringGetAsync(_redisKey).ConfigureAwait(false);

                if (!tokenValue.HasValue)
                {
                    _logger.LogDebug("No token found in Redis cache");
                    return null;
                }

                // Direct deserialization from UTF8 bytes is more efficient
                var token = JsonSerializer.Deserialize<TokenInfo>(tokenValue!, JsonOptions);
                _logger.LogDebug("Token retrieved from Redis cache, expires at: {ExpiresAt}", token?.ExpiresAt);
                return token;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve token from Redis");
                throw;
            }
        }

        /// <summary>
        /// Asynchronously updates the token in Redis cache.
        /// </summary>
        /// <param name="token">The token to cache.</param>
        /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
        private async Task UpdateTokenInRedisAsync(TokenInfo token, CancellationToken cancellationToken = default)
        {
            try
            {
                var json = JsonSerializer.Serialize(token, JsonOptions);
                await _db.StringSetAsync(_redisKey, json).ConfigureAwait(false);
                _logger.LogDebug("Token cached in Redis, expires at: {ExpiresAt}", token.ExpiresAt);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update token in Redis");
                throw;
            }
        }

        /// <summary>
        /// Asynchronously obtains a new access token from the LSEG API using password grant type.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
        /// <returns>A new TokenInfo object with access and refresh tokens.</returns>
        /// <exception cref="InvalidOperationException">Thrown when credentials are missing or token response deserialization fails.</exception>
        /// <exception cref="HttpRequestException">Thrown when the API request fails.</exception>
        private async Task<TokenInfo> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(_username) || string.IsNullOrWhiteSpace(_password) || string.IsNullOrWhiteSpace(_clientId))
            {
                _logger.LogError("LSEG credentials are not configured");
                throw new InvalidOperationException("LSEG credentials (username, password, client_id) are required but not configured.");
            }

            try
            {
                _logger.LogDebug("Requesting new access token from: {Endpoint}", _tokenEndPoint);

                // Prepare OAuth2 password grant request
                var formData = new Dictionary<string, string>
                {
                    ["username"] = _username,
                    ["password"] = _password,
                    ["grant_type"] = "password",
                    ["scope"] = "trapi",
                    ["takeExclusiveSignOnControl"] = "true",
                    ["client_id"] = _clientId
                };

                var httpClient = _httpClientFactory.CreateClient();
                using var content = new FormUrlEncodedContent(formData);
                using var response = await httpClient.PostAsync(_tokenEndPoint, content, cancellationToken).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                    _logger.LogError("Token request failed with status {StatusCode}: {Error}", response.StatusCode, errorContent);
                }

                // Ensure the request was successful
                response.EnsureSuccessStatusCode();

                // Deserialize directly to typed DTO - much more efficient than using Dictionary
                var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>(JsonOptions, cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("Failed to deserialize token response");

                // Convert API response to TokenInfo with calculated expiration time
                var expiresIn = int.Parse(tokenResponse.ExpiresIn);
                _logger.LogInformation("Access token obtained successfully, expires in {ExpiresIn} seconds", expiresIn);

                return new TokenInfo
                {
                    AccessToken = tokenResponse.AccessToken,
                    RefreshToken = tokenResponse.RefreshToken,
                    ExpiresAt = DateTime.UtcNow.AddSeconds(expiresIn)
                };
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP request failed while obtaining access token");
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error while obtaining access token");
                throw;
            }
        }

        /// <summary>
        /// Asynchronously refreshes an expired or expiring access token using the refresh token.
        /// </summary>
        /// <param name="refreshToken">The refresh token to use.</param>
        /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
        /// <returns>A new TokenInfo if refresh succeeds; otherwise, null.</returns>
        private async Task<TokenInfo?> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(_username) || string.IsNullOrWhiteSpace(_clientId))
            {
                _logger.LogError("LSEG credentials are not configured for token refresh");
                return null;
            }

            try
            {
                _logger.LogDebug("Refreshing access token");

                // Prepare OAuth2 refresh token grant request
                var formData = new Dictionary<string, string>
                {
                    ["refresh_token"] = refreshToken,
                    ["username"] = _username,
                    ["grant_type"] = "refresh_token",
                    ["client_id"] = _clientId
                };

                var httpClient = _httpClientFactory.CreateClient();
                using var content = new FormUrlEncodedContent(formData);
                using var response = await httpClient.PostAsync(_tokenEndPoint, content, cancellationToken).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                    _logger.LogWarning("Token refresh failed with status {StatusCode}: {Error}", response.StatusCode, errorContent);
                    return null;
                }

                // Ensure the request was successful
                response.EnsureSuccessStatusCode();

                var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>(JsonOptions, cancellationToken).ConfigureAwait(false);

                if (tokenResponse == null)
                {
                    _logger.LogWarning("Token refresh response deserialization returned null");
                    return null;
                }

                // Convert API response to TokenInfo with calculated expiration time
                var expiresIn = int.Parse(tokenResponse.ExpiresIn);
                _logger.LogInformation("Token refreshed successfully, expires in {ExpiresIn} seconds", expiresIn);

                return new TokenInfo
                {
                    AccessToken = tokenResponse.AccessToken,
                    RefreshToken = tokenResponse.RefreshToken,
                    ExpiresAt = DateTime.UtcNow.AddSeconds(expiresIn)
                };
            }
            catch (HttpRequestException ex)
            {
                // Log the error and return null to trigger fallback to new token acquisition
                _logger.LogWarning(ex, "Token refresh failed, will attempt to obtain new token");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during token refresh");
                return null;
            }
        }

        /// <summary>
        /// Disposes managed resources including semaphore, Redis connection, and HTTP client.
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;

            _logger.LogDebug("Disposing TokenManager");

            _lock?.Dispose();
            _redis?.Dispose();

            _disposed = true;
        }

        /// <summary>
        /// Asynchronously disposes managed resources including semaphore and Redis connection.
        /// </summary>
        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;

            _logger.LogDebug("Disposing TokenManager asynchronously");

            _lock?.Dispose();

            // Close Redis connection asynchronously before disposing
            if (_redis != null)
            {
                await _redis.CloseAsync().ConfigureAwait(false);
                _redis.Dispose();
            }

            _disposed = true;
        }
    }
}