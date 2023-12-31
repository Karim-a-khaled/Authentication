﻿
using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        public string UserName { get; set; } = string.Empty;
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string? ResetPasswordOtp { get; set; }
        public string? PhoneNumber { get; set; }
        public DateTime? ResetPasswordOtpExpiryDate { get; set; }
        public ICollection<Role> Roles { get; set; }
    }
}
