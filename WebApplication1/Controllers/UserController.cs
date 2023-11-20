using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApplication1.Data;
using WebApplication1.Models;
using WebApplication1.Services;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        private readonly UserService _userService;
        private readonly DataContext _context;

        public UserController(IConfiguration configuration, UserService userService, DataContext context)
        {
            _configuration = configuration;
            _userService = userService;
            _context = context;
        }

        [HttpGet, Authorize]
        public ActionResult<string> sayHello()
        {
            return Ok("Hello");
        }

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            user.Email = request.Email;
            user.PasswordHash = passwordHash;

            return Ok(user);
        }


        [HttpPost("login")]
        public ActionResult<User> Login(UserDto request)
        {
            if (user.Email != request.Email)
            {
                return BadRequest("Email Or Password Are Incorrect.");
            }

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                return BadRequest("Email Or Password Are Incorrect.");
            }

            string token = CreateToken(user);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim> 
            {
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(ClaimTypes.Role, "User"),
            };

            var key = _configuration.GetSection("AppSettings:Token").Value!;
            var encoding = Encoding.UTF8.GetBytes(key);
            var encodedKey = new SymmetricSecurityKey(encoding);

            var creds = new SigningCredentials(encodedKey, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: creds
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            //var user = await _context.Users.FirstOrDefaultAsync(uint => uint.Email == email);
            if (user is null) { return BadRequest("User Was Not Found");}
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
            user.ResetPasswordToken = token;
            user.ResetPasswordTokenExpiryDate = DateTime.Now.AddDays(1); ;

            return Ok("Here is Your Token : " + token + " You May Now Reset your Password");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword request)
        {
            // here you need to fetch the user from DB
            //var user = await _context Users.FirstOrDefaultAsync(u => u.PasswordResetToken == request.Token);
            if(user is null || user.ResetPasswordTokenExpiryDate < DateTime.Now)
            {
                return BadRequest("Invalid Token");
            }

            CreatePasswordHash(request.Password, out string passwordHash);
            user.PasswordHash = passwordHash;
            user.ResetPasswordToken = null;
            user.ResetPasswordTokenExpiryDate = null;

            return Ok("Password Succefully Reseted");
        }

        public static void CreatePasswordHash(string password, out string passwordHash)
        {
            using var sha256 = SHA256.Create();
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] hashBytes = sha256.ComputeHash(passwordBytes);
            passwordHash = Convert.ToBase64String(hashBytes);
        }
    }
}
