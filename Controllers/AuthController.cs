using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        // Dictionary to store usernames and passwords
        private static ConcurrentDictionary<string, string> users = new ConcurrentDictionary<string, string>();

        private readonly string key = "X2u!wZ8y$5e%vG7hJ9kL1mN2qP4rS6tU"; // Make sure this key is at least 32 characters long

        // Endpoint to register a new user
        [HttpPost("register")]
        public IActionResult Register([FromBody] UserLogin userLogin)
        {
            if (string.IsNullOrEmpty(userLogin.Username) || string.IsNullOrEmpty(userLogin.Password))
            {
                return BadRequest("Username and password must not be empty.");
            }

            if (!users.TryAdd(userLogin.Username, userLogin.Password))
            {
                return BadRequest("User already exists.");
            }

            return Ok("User registered successfully.");
        }

        // Endpoint to login and generate a JWT token
        [HttpPost("login")]
        public IActionResult Login([FromBody] UserLogin userLogin)
        {
            if (users.TryGetValue(userLogin.Username, out var storedPassword))
            {
                if (storedPassword == userLogin.Password)
                {
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var key = Encoding.ASCII.GetBytes(this.key);
                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(new Claim[]
                        {
                            new Claim(ClaimTypes.Name, userLogin.Username)
                        }),
                        Expires = DateTime.UtcNow.AddHours(1),
                        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                    };
                    var token = tokenHandler.CreateToken(tokenDescriptor);
                    var tokenString = tokenHandler.WriteToken(token);

                    return Ok(new { Token = tokenString });
                }
                return Unauthorized("Invalid password.");
            }
            return Unauthorized("User not found.");
        }

        //[HttpPost("login")]
        //public IActionResult Login([FromBody] UserLogin userLogin)
        //{
        //    // This is just a sample. In a real application, you should validate the user's credentials.
        //    if (userLogin.Username != "test" || userLogin.Password != "password")
        //    {
        //        return Unauthorized();
        //    }

        //    var tokenHandler = new JwtSecurityTokenHandler();
        //    var key = Encoding.ASCII.GetBytes("X2u!wZ8y$5e%vG7hJ9kL1mN2qP4rS6tU");
        //    var tokenDescriptor = new SecurityTokenDescriptor
        //    {
        //        Subject = new ClaimsIdentity(new Claim[]
        //        {
        //            new Claim(ClaimTypes.Name, userLogin.Username)
        //        }),
        //        Expires = DateTime.UtcNow.AddHours(1),
        //        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        //    };
        //    var token = tokenHandler.CreateToken(tokenDescriptor);
        //    var tokenString = tokenHandler.WriteToken(token);

        //    return Ok(new { Token = tokenString });
        //}
    }

    public class UserLogin
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}