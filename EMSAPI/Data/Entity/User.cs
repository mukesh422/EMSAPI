using System.ComponentModel.DataAnnotations;

namespace EMSAPI.Data.Entity
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Mobile { get; set; }
        public string Gender { get; set; }
        public string Password { get; set; }
        public string Address { get; set; }
        public string RefreshToken { get; set; }
        public string ExpiryTime { get; set; }
        public DateTime DOB { get; set; }
    }
}
