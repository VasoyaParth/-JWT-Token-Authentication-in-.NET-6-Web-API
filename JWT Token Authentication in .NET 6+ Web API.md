# JWT Token Authentication in .NET 6+ Web API

## Step 1: Install Required Packages
Run the following commands in the **Package Manager Console**:

- `Install-Package Microsoft.AspNetCore.Authentication.JwtBearer`  
  *Note: If the latest version is not supported or compatible with your .NET version, consider using an older, stable version like `8.0.13` of `Microsoft.AspNetCore.Authentication.JwtBearer` or any other compatible version.*

- `Install-Package Microsoft.IdentityModel.Tokens`  
- `Install-Package System.IdentityModel.Tokens.Jwt`


## Step 2: Configure `appsettings.json`

Add the following sections inside `appsettings.json`:

```json
{
  "Jwt": {
    "Key": "ThisIsASecretKeyForJWTTokenAuthentication", 
    // Use a strong, random key for better security.
    // Example: Generate a secure key using tools like OpenSSL or any online key generator.

    "Issuer": "https://localhost:5001", 
    // Issuer: This is the server that issues the token. 
    // Typically, it's the URL of your API (e.g., https://localhost:5001 or your deployed API URL).

    "Audience": "https://localhost:5001" 
    // Audience: The intended recipient of the token. 
    // Usually, it's the same as your API URL (e.g., https://localhost:5001).
  },
  "ConnectionStrings": {
    "ConnectionString": "Your_SQL_Server_Connection_String_Here"
    // Your database connection string goes here.
  }
}
```
## Step 3: Configure JWT Authentication in Program.cs

Add the following code inside `Program.cs` to configure JWT authentication:

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSettings["Key"]);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        ClockSkew = TimeSpan.Zero
    };
});

```
## Step 4: Create `LoginModel.cs`

If you already have a model similar to the `LoginModel` (such as a `UserLoginModel`), you can reuse it. Otherwise, create a new model as shown below.

### If you already have a model:
If your existing model looks similar (e.g., `UserLoginModel`), you can **skip creating this model** and just use it in your `AuthController`.

```csharp
public class UserLoginModel
{
    [Required]
    public string Username { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }
}
```
## Step 5: Create `AuthController.cs`

Create a new controller `AuthController.cs` inside the `Controllers` folder.

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using YourNamespace.Models;
using YourNamespace.Repositories; // Add the appropriate namespace for UserRepository

namespace YourNamespace.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserRepository _userRepository;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;

        public AuthController(UserRepository userRepository, IConfiguration configuration, ILogger<AuthController> logger)
        {
            _userRepository = userRepository;
            _configuration = configuration;
            _logger = logger;
        }

        // POST: api/Auth/Login
        [HttpPost("Login")]
        public IActionResult Login([FromBody] UserLoginModel userLoginModel)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new { message = "Invalid login data." });
                }

                // Call the Login method from the repository
                var result = _userRepository.Login(userLoginModel);

                // If login is successful, generate a JWT token
                if (result.Success)
                {
                    var token = GenerateJwtToken(result.UserId, userLoginModel.Username, result.Role);

                    // Return success response with token and user details
                    return Ok(new
                    {
                        userId = result.UserId,
                        username = userLoginModel.Username,
                        role = result.Role,
                        token = token,
                        message = result.Message
                    });
                }
                else
                {
                    // Return Unauthorized if login fails
                    return Unauthorized(new { message = result.Message });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error occurred during login.");
                return StatusCode(500, new { message = "Unexpected error occurred. Please try again." });
            }
        }

        private string GenerateJwtToken(string userId, string username, string role)
        {
            // Retrieve JWT settings from configuration
            var jwtSettings = _configuration.GetSection("Jwt");
            var key = Encoding.UTF8.GetBytes(jwtSettings["Key"]);

            // Define the claims (user details) that will be embedded in the JWT
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role)
            };

            // Set token properties (issuer, audience, expiration, etc.)
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(3), // Token expiry time
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = jwtSettings["Issuer"],
                Audience = jwtSettings["Audience"]
            };

            // Create and return the JWT token
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
```
# Step 6: Implement Login and JWT Token Management in ASP.NET Core

This guide demonstrates how to handle user login, generate a **JWT token** on successful login, store the **JWT token** and user details in the session on the client-side, and authenticate users using the stored JWT token in subsequent API calls.

---

### `LoginResponseModel.cs`

The `LoginResponseModel` represents the response from the API after a successful login, including the **JWT token**, **UserID**, **Username**, and **Role**.

```csharp
namespace YourNamespace.Models
{
    public class LoginResponseModel
    {
        public string UserID { get; set; }
        public string Username { get; set; }
        public string Role { get; set; }
        public string Token { get; set; } // This will hold the JWT Token
    }
}
```
# Step 7: User Login and JWT Token Management in ASP.NET Core

In this step, we implement the **UserController** to handle login logic, make an API call to authenticate the user, and store the **JWT token** in the session after a successful login. The **JWT token** will be used for subsequent API calls that require authentication.

---

### `UserController.cs`

This controller includes an endpoint to handle the login functionality. Upon successful login, the JWT token and user details (UserID, Username, and Role) are stored in the session.

```csharp
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Net.Http;
using System.Text;
using YourNamespace.Models;

namespace YourNamespace.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly string _apiBaseUrl = "https://your-api-url"; // Base URL of the API

        public UserController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        // POST: Handle login via API
        [HttpPost("Login")]
        public async Task<IActionResult> UserLogin([FromBody] UserLoginModel userLoginModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new { message = "Invalid login data." });
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                var endpoint = $"{_apiBaseUrl}/User/Login"; // Append endpoint to base URL

                var jsonData = JsonConvert.SerializeObject(userLoginModel);
                var content = new StringContent(jsonData, Encoding.UTF8, "application/json");

                var response = await client.PostAsync(endpoint, content);

                if (response.IsSuccessStatusCode)
                {
                    var result = JsonConvert.DeserializeObject<LoginResponseModel>(await response.Content.ReadAsStringAsync());

                    if (result != null)
                    {
                        // Store JWT Token in session
                        HttpContext.Session.SetString("Token", result.Token);  // Store the JWT token in session
                        HttpContext.Session.SetString("UserID", result.UserID); 
                        HttpContext.Session.SetString("Username", result.Username);
                        HttpContext.Session.SetString("Role", result.Role);

                        // Redirect to Dashboard
                        return RedirectToAction("DashboardView", "Dashboard");
                    }
                }

                // Return error if login fails
                return Unauthorized(new { message = "Invalid username or password." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Unexpected error occurred during login.", error = ex.Message });
            }
        }
    }
}
```
# Step 8: Passing JWT Token from UI to API

In this step, we will modify the **UI controller** to pass the **JWT token** in the **Authorization header** when making a request to the API. This ensures that the request to the API is authenticated using the stored JWT token.

---

### `CustomerController.cs`

In the UI controller, we retrieve the **JWT token** from the session and add it to the **Authorization header** as a **Bearer token** when making the **HTTP GET request** to the API. This allows the API to authenticate the request using the provided JWT token.

```csharp
#region Customer List
public async Task<IActionResult> CustomerList()
{
    List<CustomerModel> customers = new List<CustomerModel>();

    try
    {
        // Retrieve the JWT token from session
        string token = HttpContext.Session.GetString("Token");

        // Check if the token exists
        if (string.IsNullOrEmpty(token))
        {
            TempData["ErrorMessage"] = "User not authenticated. Please log in.";
            return RedirectToAction("Login", "User");
        }

        // Create a request to the API
        var request = new HttpRequestMessage(HttpMethod.Get, $"{_apiBaseUrl}/customer/getall");

        // Add the JWT token to the Authorization header as a Bearer token
        request.Headers.Add("Authorization", $"Bearer {token}");

        // Send the HTTP GET request to the API
        HttpResponseMessage response = await _httpClient.SendAsync(request);

        // Check if the response is successful
        if (response.IsSuccessStatusCode)
        {
            string data = await response.Content.ReadAsStringAsync();
            customers = JsonConvert.DeserializeObject<List<CustomerModel>>(data);
        }
        else
        {
            TempData["ErrorMessage"] = "Unable to fetch customer data. Please try again later.";
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Exception: {ex.Message}");
        TempData["ErrorMessage"] = "An unexpected error occurred while fetching customer data.";
    }

    return View("CustomerList", customers);
}
#endregion
```

# Step 9: Authenticating API Requests Using JWT Token

In this step, we will modify the **API controller** to authenticate incoming requests by validating the **JWT token** passed in the **Authorization header**. This ensures that the API only processes requests from authenticated users.

---

### `CustomerController.cs` (API Side)

We will add the logic to check the **Authorization header** for a valid **JWT token** before allowing access to the `GetAllCustomers` endpoint. If the token is invalid or missing, the API will return an **Unauthorized** response.

```csharp
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using ApnaInventory.Models;
using ApnaInventory.Repositories;
using Microsoft.AspNetCore.Authorization; // Add this for authorization
using Microsoft.AspNetCore.Http; // Add this for HTTP context

namespace ApnaInventory.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CustomerController : ControllerBase
    {
        private readonly CustomerRepository _repository;

        public CustomerController(CustomerRepository repository)
        {
            _repository = repository;
        }

        // GET: api/customer/getall
        [HttpGet("getall")]
        [Authorize] // Add this to require authorization
        public IActionResult GetAllCustomers()
        {
            // Retrieve the list of customers from the repository
            List<Customer> customers = _repository.GetAllCustomers();
            return Ok(customers);
        }
    }
}
```

### Take This as a Reference
Use this JWT token authentication implementation as a reference to integrate secure authentication in your own project. Follow the steps outlined to implement and customize the solution as needed.


## Thank you
