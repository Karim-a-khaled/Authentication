using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class ResetPassword
    {
        [Required]
        public string Token { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
