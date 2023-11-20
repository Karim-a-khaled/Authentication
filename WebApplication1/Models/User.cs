﻿namespace WebApplication1.Models
{
    public class User
    {
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string ResetPasswordToken { get; set; }
        public DateTime ResetPasswordExpiryDate { get; set; }
    }
}
