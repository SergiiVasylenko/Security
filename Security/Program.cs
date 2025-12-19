var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Bind and register repository with connection string
var connString = builder.Configuration.GetConnectionString("SafeVault") ?? "Data Source=safevault.db";
builder.Services.AddSingleton(new Security.Data.UsersRepository(connString));
builder.Services.AddControllers();
builder.Services.AddRouting(options => options.LowercaseUrls = true);

// JWT Authentication & Authorization
var jwtSection = builder.Configuration.GetSection("Jwt");
var jwtKey = jwtSection.GetValue<string>("Key") ?? "dev-only-key";
var jwtIssuer = jwtSection.GetValue<string>("Issuer") ?? "SafeVault";
var jwtAudience = jwtSection.GetValue<string>("Audience") ?? "SafeVaultClients";
var jwtExpires = jwtSection.GetValue<int>("ExpiresMinutes", 60);

builder.Services.AddAuthentication(Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

// Serve the demo web form at /webform.html from wwwroot

// Secure submit endpoint with server-side validation and parameterized queries
app.MapPost("/submit", async (
    Security.Models.UserInputDto input,
    Security.Data.UsersRepository repo,
    HttpContext http
) =>
{
    // Model binding already validates DataAnnotations; check ModelState-like behavior in minimal API
    // In minimal APIs, invalid model will result in automatic 400 if [ApiController] metadata is used.
    // We handle simple manual validation here.
    var validationProblems = new List<string>();
    if (string.IsNullOrWhiteSpace(input.Username)) validationProblems.Add("Username is required.");
    if (string.IsNullOrWhiteSpace(input.Email)) validationProblems.Add("Email is required.");
    if (input.Username.Length < 3 || input.Username.Length > 100) validationProblems.Add("Username length out of range.");
    if (input.Email.Length > 100) validationProblems.Add("Email too long.");
    if (!System.Text.RegularExpressions.Regex.IsMatch(input.Username, "^[A-Za-z0-9_.-]+$")) validationProblems.Add("Username contains invalid characters.");
    try
    {
        var addr = new System.Net.Mail.MailAddress(input.Email);
        if (addr.Address != input.Email) validationProblems.Add("Invalid email.");
    }
    catch { validationProblems.Add("Invalid email."); }

    // Sanitization and danger checks
    var userChanged = false;
    var emailChanged = false;
    if (Security.Services.InputSanitizer.IsDangerous(input.Username) || Security.Services.InputSanitizer.IsDangerous(input.Email))
    {
        validationProblems.Add("Input contains potentially dangerous content.");
    }
    var sanitizedUsername = Security.Services.InputSanitizer.SanitizeUsername(input.Username, out userChanged);
    string sanitizedEmail;
    try
    {
        sanitizedEmail = Security.Services.InputSanitizer.SanitizeEmail(input.Email, out emailChanged);
    }
    catch
    {
        validationProblems.Add("Invalid email.");
        sanitizedEmail = input.Email;
    }

    // Reject if sanitization changed content to avoid ambiguous transformations
    if (userChanged)
        validationProblems.Add("Username contains invalid characters.");
    if (emailChanged)
        validationProblems.Add("Email contains invalid characters.");

    if (validationProblems.Count > 0)
    {
        return Results.BadRequest(new { error = string.Join(" ", validationProblems) });
    }

    // Insert safely via parameterized query
    var id = repo.InsertUser(sanitizedUsername, sanitizedEmail);
    return Results.Ok(new { userId = id });
})
.WithName("SubmitUser");

// Safe read endpoint; outputs JSON which escapes HTML characters by default
app.MapGet("/users/{id:long}", (long id, Security.Data.UsersRepository repo) =>
{
    var user = repo.GetUser(id);
    return user is null
        ? Results.NotFound()
        : Results.Ok(new { user.Value.UserID, user.Value.Username, user.Value.Email });
}).WithName("GetUser");

// Register: creates user with hashed password and role
app.MapPost("/auth/register", (Security.Models.RegisterDto dto, Security.Data.UsersRepository repo) =>
{
    var changedU = false; var changedE = false;
    var username = Security.Services.InputSanitizer.SanitizeUsername(dto.Username, out changedU);
    string email;
    try { email = Security.Services.InputSanitizer.SanitizeEmail(dto.Email, out changedE); }
    catch { return Results.BadRequest(new { error = "Invalid email." }); }
    if (changedU || changedE || Security.Services.InputSanitizer.IsDangerous(dto.Password))
        return Results.BadRequest(new { error = "Invalid input." });
    if (dto.Role != "Admin" && dto.Role != "User")
        return Results.BadRequest(new { error = "Invalid role." });

    var (hash, salt) = Security.Services.PasswordHasher.HashPassword(dto.Password);
    try
    {
        var id = repo.RegisterUser(username, email, hash, salt, dto.Role);
        return Results.Ok(new { userId = id });
    }
    catch (InvalidOperationException ex)
    {
        return Results.Conflict(new { error = ex.Message });
    }
}).WithName("Register");

// Login: returns JWT if credentials are valid
app.MapPost("/auth/login", (Security.Models.LoginDto dto, Security.Data.UsersRepository repo) =>
{
    var changed = false;
    var username = Security.Services.InputSanitizer.SanitizeUsername(dto.Username, out changed);
    if (changed) return Results.BadRequest(new { error = "Invalid username." });
    var user = repo.GetAuthUser(username);
    if (user is null || string.IsNullOrEmpty(user?.PasswordHash) || string.IsNullOrEmpty(user?.PasswordSalt))
        return Results.Unauthorized();

    if (!Security.Services.PasswordHasher.Verify(dto.Password, user.Value.PasswordHash!, user.Value.PasswordSalt!))
        return Results.Unauthorized();

    var claims = new[]
    {
        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, user.Value.Username),
        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, user.Value.Role)
    };
    var creds = new Microsoft.IdentityModel.Tokens.SigningCredentials(
        new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(jwtKey)),
        Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256
    );
    var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(jwtExpires),
        signingCredentials: creds
    );
    var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
    return Results.Ok(new { token = jwt });
}).WithName("Login");

// Admin-only endpoint example
app.MapGet("/admin/secure", () => Results.Ok(new { message = "Admin access granted" }))
   .RequireAuthorization("AdminOnly")
   .WithName("AdminSecure");

// Admin-only dashboard (HTML)
app.MapGet("/admin/dashboard", (System.Security.Claims.ClaimsPrincipal user) =>
{
    var name = user.Identity?.Name ?? "admin";
    var html = $"<!doctype html><html><head><meta charset=\"utf-8\"><title>Admin Dashboard</title></head><body><h1>Welcome, {System.Net.WebUtility.HtmlEncode(name)}</h1><p>Admin Dashboard</p></body></html>";
    return Results.Content(html, "text/html; charset=utf-8");
})
.RequireAuthorization("AdminOnly")
.WithName("AdminDashboard");

// Lookup by username using parameterized query under the hood
app.MapGet("/users/by-username/{username}", (string username, Security.Data.UsersRepository repo) =>
{
    // Validate and reject if sanitization would change input (avoid ambiguous behavior)
    var changed = false;
    var cleaned = Security.Services.InputSanitizer.SanitizeUsername(username, out changed);
    if (changed || Security.Services.InputSanitizer.IsDangerous(username) || string.IsNullOrWhiteSpace(cleaned))
        return Results.BadRequest(new { error = "Invalid username." });

    var user = repo.GetUserByUsername(cleaned);
    return user is null
        ? Results.NotFound()
        : Results.Ok(new { user.Value.UserID, user.Value.Username, user.Value.Email });
}).WithName("GetUserByUsername");

// Search users safely with escaped LIKE pattern and parameter binding
app.MapGet("/users/search", (string term, Security.Data.UsersRepository repo) =>
{
    term = (term ?? string.Empty).Trim();
    if (term.Length > 100) term = term.Substring(0, 100);
    if (Security.Services.InputSanitizer.IsDangerous(term))
        return Results.BadRequest(new { error = "Search term contains dangerous content." });

    var results = repo.SearchUsers(term);
    return Results.Ok(results.Select(u => new { u.UserID, u.Username, u.Email }));
}).WithName("SearchUsers");

app.Run();

public partial class Program { }

