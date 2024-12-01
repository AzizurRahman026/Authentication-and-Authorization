
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
```
