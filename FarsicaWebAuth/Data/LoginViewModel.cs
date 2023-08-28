using System.ComponentModel.DataAnnotations;

namespace Farsica.WebAuth.Data
{
    public class LoginViewModel
    {
        [Required]
        [Display(Name = "Username")]
        public string? Username { get; set; }
    }
}
