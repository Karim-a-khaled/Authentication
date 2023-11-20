using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
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
        public ActionResult<string> SayHello()
        {
            return Ok("Hello");
        }

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            string passwordHash = HashPassword(request.Password);

            user.Email = request.Email;
            user.PasswordHash = passwordHash;

            return Ok(user);
        }

        [HttpPost("login")]
        public ActionResult<User> Login(UserDto request)
        {
            if (user.Email != request.Email)
            {
                return BadRequest("Email or Password is incorrect.");
            }

            if (!VerifyPassword(request.Password, user.PasswordHash))
            {
                return BadRequest("Email or Password is incorrect.");
            }

            string token = GenerateJwtToken(user);

            return Ok(token);
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            // var user = await _context.Users.FirstOrDefaultAsync(uint => uint.Email == email);
            if (user is null)
            {
                return BadRequest("User was not found");
            }

            var otp = GenerateRandomOTP();

            var OtpExpirationInSeconds = int.Parse(_configuration.GetSection("AppSettings:OtpExpirationInSeconds").Value!);
            var expirationInSeconds = OtpExpirationInSeconds;

            var expirationDate = DateTime.Now.AddSeconds(expirationInSeconds); 

            user.ResetPasswordOtp = otp; 
            user.ResetPasswordOtpExpiryDate = expirationDate;

            return Ok("You may now reset your password. Here is your OTP: " + otp);
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword request)
        {
            //var user = await _context Users.FirstOrDefaultAsync(u => u.PasswordResetToken == request.Token);
            if (user is null || user.ResetPasswordOtpExpiryDate < DateTime.Now)
            {
                return BadRequest("Invalid token");
            }

            string passwordHash = HashPassword(request.Password);
            user.PasswordHash = passwordHash;
            user.ResetPasswordOtp = null;
            user.ResetPasswordOtpExpiryDate = null;

            return Ok("Password successfully reset");
        }

        private string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] hashBytes = sha256.ComputeHash(passwordBytes);
            return Convert.ToBase64String(hashBytes);
        }

        private bool VerifyPassword(string password, string passwordHash)
        {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }

        private string GenerateRandomOTP()
        {
            Random random = new Random();
            int otp = random.Next(1000, 9999);
            return otp.ToString("D4");
        }

        private string GenerateJwtToken(User user)
        {
            var key = _configuration.GetSection("AppSettings:Token").Value!;
            var encoding = Encoding.UTF8.GetBytes(key);
            var encodedKey = new SymmetricSecurityKey(encoding);
            var creds = new SigningCredentials(encodedKey, SecurityAlgorithms.HmacSha512Signature);

            var TokenExpirationInDays = int.Parse(_configuration.GetSection("AppSettings:TokenExpires").Value!);
            var expirationInDays = TokenExpirationInDays;

            var expirationDate = DateTime.Now.AddDays(expirationInDays); 

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(ClaimTypes.Role, "User")
            };



            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


    }
}