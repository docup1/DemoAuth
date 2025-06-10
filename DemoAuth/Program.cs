using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using BCrypt.Net;
using System.Net;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Annotations;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace AuthService
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services
            builder.Services.AddDbContext<AuthDbContext>(options =>
                options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

            // Настройка аутентификации с приоритетом HttpOnly cookies
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = builder.Configuration["Jwt:Issuer"],
                        ValidAudience = builder.Configuration["Jwt:Audience"],
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
                    };

                    // Приоритет HttpOnly cookie над заголовком Authorization
                    options.Events = new JwtBearerEvents
                    {
                        OnMessageReceived = context =>
                        {
                            // Сначала проверяем HttpOnly cookie (основной способ в production)
                            var token = context.Request.Cookies["accessToken"];

                            // Если токена нет в cookie, проверяем заголовок Authorization (для тестирования в Swagger)
                            if (string.IsNullOrEmpty(token))
                            {
                                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                                if (authHeader != null && authHeader.StartsWith("Bearer "))
                                {
                                    token = authHeader.Substring("Bearer ".Length).Trim();
                                }
                            }

                            if (!string.IsNullOrEmpty(token))
                            {
                                context.Token = token;
                            }

                            return Task.CompletedTask;
                        }
                    };
                });

            // Add authorization services
            builder.Services.AddAuthorization();

            builder.Services.AddRateLimiter(options =>
            {
                options.AddFixedWindowLimiter("RegisterLimit", opt =>
                {
                    opt.PermitLimit = 10;
                    opt.Window = TimeSpan.FromHours(1);
                    opt.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
                    opt.QueueLimit = 0;
                });
                options.AddFixedWindowLimiter("LoginLimit", opt =>
                {
                    opt.PermitLimit = 5;
                    opt.Window = TimeSpan.FromMinutes(1);
                    opt.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
                    opt.QueueLimit = 0;
                });
            });

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowCredentials", builder =>
                    builder
                        .SetIsOriginAllowed(origin => true) // Разрешаем все источники для разработки
                        .AllowAnyMethod()
                        .AllowAnyHeader()
                        .AllowCredentials()); // Важно для работы с cookies
            });

            // Add Swagger
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "Minimal Authorization Service API",
                    Version = "v1",
                    Description = "A simple authorization service using JWT tokens stored in HttpOnly cookies. Supports registration, login, user info, and logout. " +
                                "Note: Authentication primarily uses HttpOnly cookies. Bearer token authentication is available for API testing in Swagger UI."
                });

                // Enable annotations
                options.EnableAnnotations();

                // Добавляем специальные заголовки для Swagger UI
                options.AddSecurityDefinition("Cookie", new OpenApiSecurityScheme
                {
                    Description = "HttpOnly Cookie authentication (automatic in production, manual in Swagger)",
                    Name = "Cookie",
                    In = ParameterLocation.Cookie,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "cookie"
                });

                // Add JWT security definition (для тестирования в Swagger)
                options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme for testing purposes. " +
                                "Example: \"Bearer {token}\". " +
                                "Use the token returned from the login endpoint.",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT"
                });

                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        Array.Empty<string>()
                    },
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Cookie"
                            }
                        },
                        Array.Empty<string>()
                    }
                });

                // Include XML comments
                var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                if (File.Exists(xmlPath))
                {
                    options.IncludeXmlComments(xmlPath);
                }
            });

            var app = builder.Build();

            app.UseCors("AllowCredentials");
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseRateLimiter();

            // Enable Swagger
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "Minimal Authorization Service API V1");
                c.RoutePrefix = "swagger"; // URL: https://deal.zirkon.pw/swagger

                c.DefaultModelsExpandDepth(-1);
                c.DocExpansion(Swashbuckle.AspNetCore.SwaggerUI.DocExpansion.None);
                c.InjectJavascript("/swagger-auth.js");
                
                // Настройки для работы с cookies в Swagger UI
                c.ConfigObject.AdditionalItems.Add("requestInterceptor", 
                    @"(request) => { 
                        request.credentials = 'include'; 
                        request.withCredentials = true;
                        
                        // Автоматически добавляем токен из cookie в заголовок для Swagger
                        const token = document.cookie
                            .split('; ')
                            .find(row => row.startsWith('accessToken='))
                            ?.split('=')[1];
                        
                        if (token && !request.headers.Authorization) {
                            request.headers.Authorization = 'Bearer ' + token;
                        }
                        
                        return request; 
                    }");
                
                // Дополнительные настройки для поддержки cookies
                c.ConfigObject.AdditionalItems.Add("responseInterceptor", 
                    @"(response) => { 
                        // Автоматически устанавливаем авторизацию в Swagger UI после логина
                        if (response.url.includes('/api/auth/login') && response.status === 200) {
                            try {
                                const data = JSON.parse(response.text);
                                if (data.token) {
                                    // Устанавливаем токен в Swagger UI
                                    window.ui.authActions.authorize({
                                        Bearer: {
                                            name: 'Bearer',
                                            schema: {
                                                type: 'http',
                                                in: 'header'
                                            },
                                            value: data.token
                                        }
                                    });
                                }
                            } catch (e) {
                                console.log('Could not auto-authorize:', e);
                            }
                        }
                        return response; 
                    }");
            });

            // Endpoints
            app.MapPost("/api/auth/register", async ([FromBody] RegisterRequest request, AuthDbContext db, IConfiguration config, HttpContext httpContext) =>
            {
                var requestId = Guid.NewGuid().ToString();
                httpContext.Response.Headers.Add("X-Request-ID", requestId);

                // Validation
                var validationErrors = ValidateRegisterRequest(request);
                if (validationErrors.Any())
                {
                    var errorDetails = validationErrors.ToDictionary(kvp => kvp.Key, kvp => string.Join(", ", kvp.Value));
                    httpContext.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    return Results.Json(new { error = "validation_failed", details = errorDetails });
                }

                // Check if login exists
                if (await db.Users.AnyAsync(u => u.Login == request.Login))
                {
                    httpContext.Response.StatusCode = (int)HttpStatusCode.Conflict;
                    return Results.Json(new { error = "user_already_exists", field = "login" });
                }

                // Create user
                var user = new User
                {
                    Id = Guid.NewGuid(),
                    Login = request.Login,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password, 12),
                    Role = "user",
                    CreatedAt = DateTime.UtcNow
                };

                db.Users.Add(user);
                await db.SaveChangesAsync();

                httpContext.Response.StatusCode = (int)HttpStatusCode.Created;
                return Results.Json(new
                {
                    id = user.Id,
                    login = user.Login,
                    message = "User registered successfully."
                });
            })
            .RequireRateLimiting("RegisterLimit")
            .WithMetadata(new SwaggerOperationAttribute("Register User", "Creates a new user account with unique login and hashed password. Rate limit: 10 requests per hour."))
            .WithTags("Authentication");

            app.MapPost("/api/auth/login", async (
                [FromBody] LoginRequest request,
                AuthDbContext db,
                IConfiguration config,
                HttpContext httpContext) =>
            {
                var requestId = Guid.NewGuid().ToString();
                httpContext.Response.Headers.Add("X-Request-ID", requestId);

                // Validation
                if (string.IsNullOrEmpty(request.Login) || string.IsNullOrEmpty(request.Password))
                {
                    httpContext.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    return Results.Json(new { error = "validation_failed", details = new[] { "login", "password" } });
                }

                var user = await db.Users.FirstOrDefaultAsync(u => u.Login == request.Login);
                if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                {
                    if (user != null)
                    {
                        user.FailedLoginAttempts++;
                        if (user.FailedLoginAttempts >= 5)
                        {
                            user.LockedUntil = DateTime.UtcNow.AddMinutes(15);
                            await db.SaveChangesAsync();
                            httpContext.Response.StatusCode = (int)HttpStatusCode.Locked;
                            return Results.Json(new { error = "account_locked", unlockAt = user.LockedUntil });
                        }
                        await db.SaveChangesAsync();
                    }
                    httpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    return Results.Json(new { error = "invalid_credentials" });
                }

                if (user.LockedUntil.HasValue && user.LockedUntil > DateTime.UtcNow)
                {
                    httpContext.Response.StatusCode = (int)HttpStatusCode.Locked;
                    return Results.Json(new { error = "account_locked", unlockAt = user.LockedUntil });
                }

                // Reset failed attempts
                user.FailedLoginAttempts = 0;
                user.LastLogin = DateTime.UtcNow;
                await db.SaveChangesAsync();

                // Generate JWT
                var token = GenerateJwtToken(user, config);

                // Determine environment and request source
                var isDevelopment = app.Environment.IsDevelopment();
                var userAgent = httpContext.Request.Headers["User-Agent"].ToString();
                var isSwaggerRequest = userAgent.Contains("swagger", StringComparison.OrdinalIgnoreCase) ||
                                       httpContext.Request.Headers["Referer"].ToString().Contains("swagger", StringComparison.OrdinalIgnoreCase);

                // Установка куки
                httpContext.Response.Cookies.Append("accessToken", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None,
                    Expires = DateTimeOffset.UtcNow.AddMinutes(60)
                });


                // Ответ без токена
                var response = new
                {
                    user = new
                    {
                        id = user.Id,
                        login = user.Login,
                        role = user.Role,
                        lastLogin = user.LastLogin
                    },
                    message = "Login successful. Authentication token is set in HttpOnly cookie."
                };

                return Results.Json(response);
            })
            .RequireRateLimiting("LoginLimit")
            .WithMetadata(new SwaggerOperationAttribute("Login User", "Authenticates user and sets JWT token in HttpOnly cookie. Rate limit: 5 requests per minute."))
            .WithTags("Authentication");


            app.MapGet("/api/auth/me", async (HttpContext httpContext, AuthDbContext db) =>
            {
                var requestId = Guid.NewGuid().ToString();
                httpContext.Response.Headers.Add("X-Request-ID", requestId);

                var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                {
                    httpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    return Results.Json(new { error = "token_missing_or_invalid" });
                }

                var user = await db.Users.FindAsync(Guid.Parse(userId));
                if (user == null)
                {
                    httpContext.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    return Results.Json(new { error = "token_missing_or_invalid" });
                }

                return Results.Json(new
                {
                    id = user.Id,
                    login = user.Login,
                    role = user.Role,
                    createdAt = user.CreatedAt,
                    lastLogin = user.LastLogin,
                    authenticationMethod = httpContext.Request.Cookies.ContainsKey("accessToken") ? "HttpOnly Cookie" : "Bearer Token"
                });
            })
            .RequireAuthorization()
            .WithMetadata(new SwaggerOperationAttribute("Get Current User", "Retrieves information about the authenticated user. Authentication is handled automatically via HttpOnly cookie."))
            .WithTags("Authentication");

            app.MapPost("/api/auth/logout", (HttpContext httpContext) =>
            {
                var requestId = Guid.NewGuid().ToString();
                httpContext.Response.Headers.Add("X-Request-ID", requestId);

                // Очищаем cookie (как HttpOnly, так и обычный)
                var isDevelopment = app.Environment.IsDevelopment();
                
                // Очищаем HttpOnly cookie
                httpContext.Response.Cookies.Append("accessToken", "", new CookieOptions
                {
                    HttpOnly = true,
                    Secure = !isDevelopment,
                    SameSite = SameSiteMode.None, // обязательно для кросс-доменных запросов
                    Expires = DateTimeOffset.UtcNow.AddDays(-1),
                    Path = "/"
                });
                
                // Очищаем обычный cookie (для Swagger)
                httpContext.Response.Cookies.Append("accessToken", "", new CookieOptions
                {
                    HttpOnly = false,
                    Secure = !isDevelopment,
                    SameSite = SameSiteMode.None, // обязательно для кросс-доменных запросов
                    Expires = DateTimeOffset.UtcNow.AddDays(-1),
                    Path = "/"
                });

                return Results.Json(new { message = "Logged out successfully. Authentication cookie has been cleared." });
            })
            .RequireAuthorization()
            .WithMetadata(new SwaggerOperationAttribute("Logout User", "Clears JWT token cookie to log out the user."))
            .WithTags("Authentication");
            
            app.MapGet("/api/auth/status", (HttpContext httpContext) =>
            {
                var requestId = Guid.NewGuid().ToString();
                httpContext.Response.Headers.Add("X-Request-ID", requestId);

                var isAuthenticated = httpContext.User.Identity?.IsAuthenticated ?? false;
                var hasCookie = httpContext.Request.Cookies.ContainsKey("accessToken");
                var hasAuthHeader = httpContext.Request.Headers.ContainsKey("Authorization");

                return Results.Json(new
                {
                    isAuthenticated = isAuthenticated,
                    hasCookie = hasCookie,
                    hasAuthorizationHeader = hasAuthHeader,
                    authenticationMethod = hasCookie ? "HttpOnly Cookie" : 
                                         hasAuthHeader ? "Bearer Token" : "None"
                });
            })
            .WithMetadata(new SwaggerOperationAttribute("Check Auth Status", "Returns current authentication status and method used."))
            .WithTags("Authentication");

            app.Run();
        }

        private static Dictionary<string, List<string>> ValidateRegisterRequest(RegisterRequest request)
        {
            var errors = new Dictionary<string, List<string>>();

            // Validate login
            if (string.IsNullOrEmpty(request.Login) || request.Login.Length < 3 || request.Login.Length > 50)
            {
                AddError(errors, "login", "Login must be between 3 and 50 characters");
            }
            if (!string.IsNullOrEmpty(request.Login) && !Regex.IsMatch(request.Login, @"^[a-zA-Z0-9\-_]+$"))
            {
                AddError(errors, "login", "Login can only contain letters, digits, hyphen, or underscore");
            }

            // Validate password
            if (string.IsNullOrEmpty(request.Password) || request.Password.Length < 8)
            {
                AddError(errors, "password", "Password must be at least 8 characters");
            }
            if (!string.IsNullOrEmpty(request.Password) && !Regex.IsMatch(request.Password, @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$"))
            {
                AddError(errors, "password", "Password must contain at least one uppercase, one lowercase, and one digit");
            }

            return errors;
        }

        private static void AddError(Dictionary<string, List<string>> errors, string key, string errorMessage)
        {
            if (!errors.ContainsKey(key))
            {
                errors[key] = new List<string>();
            }
            errors[key].Add(errorMessage);
        }

        private static string GenerateJwtToken(User user, IConfiguration config)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Login),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: config["Jwt:Issuer"],
                audience: config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public class RegisterRequest
    {
        public string Login { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class LoginRequest
    {
        public string Login { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class User
    {
        public Guid Id { get; set; }
        [MaxLength(50)]
        public string Login { get; set; } = string.Empty;
        [MaxLength(255)]
        public string PasswordHash { get; set; } = string.Empty;
        [MaxLength(20)]
        public string Role { get; set; } = "user";
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLogin { get; set; }
        public DateTime? LockedUntil { get; set; }
        public int FailedLoginAttempts { get; set; } = 0;
    }

    public class AuthDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>()
                .HasIndex(u => u.Login)
                .IsUnique();
        }
    }
}