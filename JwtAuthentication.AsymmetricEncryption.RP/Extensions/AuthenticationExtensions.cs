using System;
using JwtAuthentication.AsymmetricEncryption.RP.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthentication.AsymmetricEncryption.RP.Extensions
{
    public static class AuthenticationExtensions
    {
        private static readonly string DefaultStagingTradeAuthAuthority =
            "https://authserver-api.dev.trade.au.csnglobal.net";

        private static readonly string DefaultProductionTradeAuthAuthority =
            "https://authserver-api.prod.trade.au.csnglobal.net";

        public static IServiceCollection AddAsymmetricAuthentication(this IServiceCollection services,
            IConfiguration configuration, IWebHostEnvironment env)
        {
            var authConfig = new Auth();
            configuration.GetSection("Auth").Bind(authConfig);

            // services.Configure<AsymmetricSecurityKey>(options =>
            //     configuration.GetSection("Auth:AsymmetricConfiguration").Bind(options));

            services.AddAuthentication(authOptions =>
                {
                    authOptions.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    authOptions.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(options =>
                {
                    options.SaveToken = false;
                    options.RequireHttpsMetadata = !env.IsDevelopment();
                    options.Authority = authConfig.AsymmetricConfiguration.Authority ?? (env.IsStaging()
                        ? DefaultStagingTradeAuthAuthority
                        : DefaultProductionTradeAuthAuthority);
                    // options.AutomaticRefreshInterval = new TimeSpan(0, 6, 0);
                    // options.RefreshInterval = new TimeSpan(0, 6, 0);
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidateIssuer = true,
                        ValidIssuer = authConfig.Issuer,
                        ValidateIssuerSigningKey = true,
                        LifetimeValidator = LifetimeValidator
                    };
                });

            return services;
        }

        private static bool LifetimeValidator(DateTime? notBefore,
            DateTime? expires,
            SecurityToken securityToken,
            TokenValidationParameters validationParameters)
        {
            return expires != null && expires > DateTime.UtcNow;
        }
    }
}