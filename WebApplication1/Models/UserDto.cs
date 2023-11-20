using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class UserDto
    {
        [EmailAddress]
        public required string Email { get; set; }
        public required string Password { get; set; }
    }
}
