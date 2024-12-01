
## 1. Add Nuget Packages 
Add the following packages from nuget package manager.

Microsoft.AspNetCore.Authentication.JwtBearer   
Microsoft.IdentityModel.Tokens   
System.IdentityModel.Tokens.Jwt   


## 2. Update setting in appsetting.json

```cpp
"JWT": {
    "Key": "SuperSecretKeyAssalamuAlikumOyarRahmatullahiOyaBarakatullahAlhamdulillahItisW",
    "Issuer": "http://localhost:27017",
    "Audience": "http://localhost:27017"
}
```

## 3. Register JWT token for Authentication in Program.cs file

```cpp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

// Add JWT Authentication configuration
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["tokenKey"])),
            ValidateIssuer = false,
            ValidateAudience = false
        };
});

app.UseAuthentication();
app.UseAuthorization();
```
## 4. Create Model

```cpp
// RegisterDTO.cs
namespace Core.Entities.DTO
{
    public class RegisterDTO
    {
        public required string Username { get; set; }
        public required string Password { get; set; }
        public required string Role { get; set; }
    }
}

// LoginDTO.cs
namespace Core.Entities.DTO
{
    public class LoginDTO
    {
        public required string Username { get; set; }
        public required string Password { get; set; }
    }
}

// UserDTO.cs
namespace Core.Entities.DTO
{
    public class UserDTO
    {

        public required string Username { get; set; }
        public required string Token { get; set; }
    }
}


```

## 5. Create a UserController
```cpp
using Core.Entities.DTO;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ECommerseApp.Controllers
{
    [ApiController]
    [Authorize]  // Apply to all actions in this controller
    public class UserController : Controller
    {
        [HttpPost("user/register")]
        [AllowAnonymous]  // Allow anonymous access to registration
        public async Task<IActionResult> RegisterUser([FromBody] RegisterDTO user)
        {
            Console.WriteLine(user.Username + " " + user.Password + " " + user.Role);
            return Ok("Register UI");
        }
    }
}

```
