namespace WebApplication1.Models
{
    public class Role
    {
        public string Name { get; set; }
        public int UserId { get; set; }
        public User User { get; set; }
    }
}
