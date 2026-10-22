using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using LDPTokenFunction;

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices((context, services) =>
    {
        //services.AddApplicationInsightsTelemetryWorkerService();
        //services.ConfigureFunctionsApplicationInsights();
        
        // Register HttpClient factory
        services.AddHttpClient();

        // Configure TokenManager options from configuration
        services.Configure<TokenManagerOptions>(options =>
        {
            var configuration = context.Configuration;
            options.RedisConnectionString = configuration["RedisConnectionString"] ?? string.Empty;
            options.RedisTokenKey = configuration["RedisTokenKey"] ?? "lseg_token";
            options.LDPUsername = configuration["LDPUsername"] ?? string.Empty;
            options.LDPPassword = configuration["LDPPassword"] ?? string.Empty;
            options.LDPClientID = configuration["LDPClientID"] ?? string.Empty;
            options.BasicAuthUsername = configuration["BasicAuthUsername"] ?? string.Empty;
            options.BasicAuthPassword = configuration["BasicAuthPassword"] ?? string.Empty;
            options.LDPTokenURL = configuration["LDPTokenURL"] ?? "https://api.refinitiv.com/auth/oauth2/v1/token";
            
            if (int.TryParse(configuration["ExpiryBufferMinutes"], out var bufferMinutes))
            {
                options.ExpiryBufferMinutes = bufferMinutes;
            }
        });

        // Register TokenManager as singleton
        services.AddSingleton<ITokenManager, TokenManager>();
    })
    .Build();

host.Run();
