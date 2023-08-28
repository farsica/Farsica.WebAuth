using Microsoft.AspNetCore.Identity;

namespace Farsica.WebAuth.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? CredentialId { get; set; }
        public string? PasswordlessPublicKey { get; set; }
    }
}
