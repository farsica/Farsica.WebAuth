#nullable disable

using Farsica.WebAuth.Data;
using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace Farsica.WebAuth.Areas.Identity.Pages.Account
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly IUserStore<ApplicationUser> userStore;
        private readonly IFido2 fido2;
        private readonly ApplicationDbContext context;

        public RegisterModel(UserManager<ApplicationUser> userManager,
            IUserStore<ApplicationUser> userStore, IFido2 fido2, ApplicationDbContext context)
        {
            this.userManager = userManager;
            this.userStore = userStore;
            this.fido2 = fido2;
            this.context = context;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }

        public async Task OnGetAsync(string returnUrl = null)
        {
            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            if (ModelState.IsValid)
            {

            }

            // If we got this far, something failed, redisplay form
            return Page();
        }

        public IActionResult OnPostCredentialOptions([FromBody] InputModel model)
        {
            var user = new Fido2User
            {
                Id = Encoding.UTF8.GetBytes(model.Username),
                Name = model.Username,
                DisplayName = $"{model.FirstName} {model.LastName}",
            };

            var options = fido2.RequestNewCredential(user, new List<PublicKeyCredentialDescriptor>());
            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            return new JsonResult(options);
        }

        public async Task<IActionResult> OnPostSaveCredentialsAsync([FromBody] AuthenticatorAttestationRawResponse attestationResponse)
        {
            try
            {
                var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
                var options = CredentialCreateOptions.FromJson(jsonOptions);

                var fidoCredentials = await fido2.MakeNewCredentialAsync(attestationResponse, options, IsCredentialUnique);

                var storedCredential = new StoredCredential
                {
                    Descriptor = new PublicKeyCredentialDescriptor(fidoCredentials.Result.CredentialId),
                    PublicKey = fidoCredentials.Result.PublicKey,
                    UserHandle = fidoCredentials.Result.User.Id,
                    SignatureCounter = fidoCredentials.Result.Counter,
                    CredType = fidoCredentials.Result.CredType,
                    RegDate = DateTime.Now,
                    AaGuid = fidoCredentials.Result.Aaguid
                };

                var names = options.User.DisplayName.Split(' ');

                ApplicationUser user = new()
                {
                    UserName = options.User.Name,
                    FirstName = names[0],
                    LastName = names[1],
                    CredentialId = Convert.ToBase64String(fidoCredentials.Result.CredentialId),
                    PasswordlessPublicKey = JsonConvert.SerializeObject(storedCredential),
                };
                await userStore.SetUserNameAsync(user, options.User.Name, CancellationToken.None);
                var result = await userManager.CreateAsync(user);

                return new JsonResult(result.Succeeded ? fidoCredentials : new Fido2.CredentialMakeResult("error", string.Join(",", result.Errors.Select(t => t.Description)), null));
            }
            catch (Exception exc)
            {
                return new JsonResult(new Fido2.CredentialMakeResult("error", exc.Message, null));
            }
        }

        private async Task<bool> IsCredentialUnique(IsCredentialIdUniqueToUserParams userParams, CancellationToken cancellationToken)
        {
            return !await context.Users.AnyAsync(t => t.CredentialId == Convert.ToBase64String(userParams.CredentialId), cancellationToken: cancellationToken);
        }

        public class InputModel
        {
            [Required]
            [Display(Name = "Username")]
            public string Username { get; set; }

            [Display(Name = "FirstName")]
            public string FirstName { get; set; }

            [Display(Name = "LastName")]
            public string LastName { get; set; }
        }
    }
}
