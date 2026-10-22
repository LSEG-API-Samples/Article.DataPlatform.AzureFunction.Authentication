namespace LDPTokenFunction
{
    /// <summary>
    /// Configuration options for TokenManager.
    /// </summary>
    public class TokenManagerOptions
    {
        /// <summary>
        /// Configuration section name for binding.
        /// </summary>
        public const string SectionName = "TokenManager";

        /// <summary>
        /// Gets or sets the Redis connection string.
        /// </summary>
        public string RedisConnectionString { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Redis key for storing tokens.
        /// </summary>
        public string RedisTokenKey { get; set; } = "lseg_token";

        /// <summary>
        /// Gets or sets the LSEG username.
        /// </summary>
        public string LDPUsername { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the LSEG password.
        /// </summary>
        public string LDPPassword { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the LSEG client ID.
        /// </summary>
        public string LDPClientID { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the basic authentication username.
        /// </summary>
        public string BasicAuthUsername { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the basic authentication password.
        /// </summary>
        public string BasicAuthPassword { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the LSEG token endpoint URL.
        /// </summary>
        public string LDPTokenURL { get; set; } = "https://api.refinitiv.com/auth/oauth2/v1/token";

        /// <summary>
        /// Gets or sets the expiry buffer in minutes before token refresh.
        /// </summary>
        public int ExpiryBufferMinutes { get; set; } = 2;

        /// <summary>
        /// Validates the configuration options.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown when required configuration is missing.</exception>
        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(RedisConnectionString))
                throw new InvalidOperationException("RedisConnectionString is required.");

            if (string.IsNullOrWhiteSpace(LDPTokenURL))
                throw new InvalidOperationException("LDPTokenURL is required.");
        }
    }
}
