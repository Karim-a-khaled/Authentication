using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class ResetPassword
    {
        [Required]
        public string Otp { get; set; }
        [Required]
        public string NewPassword { get; set; }
    }
}
