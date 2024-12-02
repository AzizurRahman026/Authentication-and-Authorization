
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
            RoleClaimType = ClaimTypes.Role,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"])),
            ValidateIssuer = false,
            ValidateAudience = false
        };
});

app.UseAuthentication();
app.UseAuthorization();
```
## 4. Create 3 DTO Model and 1 user model

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


// User.cs
namespace Core.Entities
{
    public class User
    {
        public required string Username { get; set; }
        public required string Password { get; set; }
        public required string Role { get; set; }
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
## 6. Create a IUserServices.cs and ITokenService.cs Interfaces
```cpp

// IUserServices.cs
using Core.Entities;
using Core.Entities.DTO;
using Microsoft.AspNetCore.Mvc;

namespace Core.Interface
{
    public interface IUserServices
    {
        Task<User> RegisterUser(RegisterDTO regiserDto);
        Task<bool> UserExist(string username);
        Task<User> Login(LoginDTO loginDto);
    }
}

// ITokenService.cs
using Core.Entities;

namespace Core.Interface
{
    public interface ITokenService
    {
        string CreateToken(User user);
    }
}

```

## 7. Implement IUserServices.cs and ITokeService.cs using UserServices.cs and TokenService.cs
```cpp
// UserServices.cs

using Core.Entities;
using Core.Entities.DTO;
using Core.Interface;
using Infrastructure.Data;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using SharpCompress.Common;

namespace Infrastructure.Services
{
    public class UserServices : IUserServices
    {

        private readonly MongoDbContext _context;

        public UserServices(MongoDbContext context)
        {
            _context = context;
        }

        public async Task<User> Login(LoginDTO loginDto)
        {
            var collection = _context.GetCollection<User>("Users");

            // Fetch user from the database
            var user = await collection.Find(u => u.Username == loginDto.Username).FirstOrDefaultAsync();

            if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.Password))
            {
                throw new Exception("Invalid username or password.");
            }

            var newUser = new User
            {
                Username = user.Username,
                Password = user.Password,
                Role = user.Role
            };
            return newUser;
        }
        
        public async Task<User> RegisterUser(RegisterDTO regiserDto)
        {
            var hashPassword = BCrypt.Net.BCrypt.HashPassword(regiserDto.Password);

            var newUser = new User
            {
                Username = regiserDto.Username,
                Password = hashPassword,
                Role = regiserDto.Role
            };
            var collection = _context.GetCollection<User>("Users"); // Dynamically get the collection
            await collection.InsertOneAsync(newUser);
            return newUser;
        }

        public async Task<bool> UserExist(string username)
        {
            var collection = _context.GetCollection<User>("Users");
            var user = await collection.Find(u => u.Username == username).FirstOrDefaultAsync();
            return user != null;
        }
    }
}


// TokenService.cs
using Core.Entities;
using Core.Interface;
using Infrastructure.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Infrastructure.Services
{
    public class TokenService : ITokenService
    {

        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public string CreateToken(User user)
        {
            // Define claims including Name and Role (or other necessary claims)
            /*var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim("role", user.Role) // Custom role claim name
            };*/
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role) // or a custom claim like "role"
            };


            // Secret key for signing the JWT (ensure this is the same as in your configuration)
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"]));

            // Credentials for signing the token
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Create JWT token with claims and expiration time
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1), // Set to 1 hour or another suitable time
                signingCredentials: creds,
                notBefore: DateTime.UtcNow // Optionally set a "NotBefore" claim
            );

            // Return the generated token as a string
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}


```

## 8. UserController Code:

```cpp
using Core.Entities.DTO;
using Core.Interface;
using Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ECommerseApp.Controllers
{
    [ApiController]
    public class UserController : Controller
    {

        private readonly IUserServices _userService;
        private readonly ITokenService _tokenService;

        public UserController(IUserServices userService, ITokenService tokenService)
        {
            _userService = userService;
            _tokenService = tokenService;
        }


        [HttpPost("user/register")]
        [AllowAnonymous]  // Allow anonymous access to registration
        public async Task<IActionResult> RegisterUser(RegisterDTO user)
        {

            Console.WriteLine("username: " + user.Username + " password: " + user.Password + " role: " + user.Role);
            if (await UserExist(user.Username))
            {
                return BadRequest("User already Exist");
            }
            var registerUser = await _userService.RegisterUser(user);

            var userDto = new UserDTO
            {
                Username = registerUser.Username,
                Token = _tokenService.CreateToken(registerUser)
            };

            return Ok(userDto);
        }

        [HttpPost("user/login")]
        [AllowAnonymous]  // Allow anonymous access to registration
        public async Task<IActionResult> Login(LoginDTO loginDto)
        {
            Console.WriteLine("login user username: " + loginDto.Username + " password: " + loginDto.Password);
            try
            {
                var loginUser = await _userService.Login(loginDto);
                var userDto = new UserDTO
                {
                    Username = loginDto.Username,
                    Token = _tokenService.CreateToken(loginUser)
                };

                return Ok(userDto);
            }
            catch (Exception ex)
            {
                return Unauthorized(new { message = ex.Message });
            }
        }


        [HttpGet("user/admin")]
        [Authorize(Roles = "admin")]
        public ActionResult AdminAuthorizationTest()
        {
            return Ok("Admin Api Accessed...");
        }

        [HttpGet("user/user")]
        [Authorize]
        public ActionResult UserAuthorizationTest()
        {
            return Ok("User Api Accessed...");
        }

        private async Task<bool> UserExist(string username)
        {
            bool haveUser = await _userService.UserExist(username);
            if (haveUser)
            {
                return true;
            }
            return false;
        }
    }
}
```

![Postman api call screen shot for role based authentication](https://github.com/user-attachments/assets/7e1f086c-34b2-4657-be45-603568f73fd6)


