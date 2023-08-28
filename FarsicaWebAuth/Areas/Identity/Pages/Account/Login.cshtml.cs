#nullable disable

using Farsica.WebAuth.Data;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;
using Fido2NetLib;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using System.Collections.Generic;
using Microsoft.Identity.Client.Platforms.Features.DesktopOs.Kerberos;
using Microsoft.EntityFrameworkCore;

namespace Farsica.WebAuth.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly ILogger<LoginModel> logger;
        private readonly IFido2 fido2;
        private readonly ApplicationDbContext context;

        public LoginModel(SignInManager<ApplicationUser> signInManager, ILogger<LoginModel> logger, IFido2 fido2, ApplicationDbContext context)
        {
            this.signInManager = signInManager;
            this.logger = logger;
            this.fido2 = fido2;
            this.context = context;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync([FromBody] AuthenticatorAssertionRawResponse clientResponse)
        {
            try
            {
                var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
                var options = AssertionOptions.FromJson(jsonOptions);

                var user = await context.Users.FirstOrDefaultAsync(t => t.CredentialId == Convert.ToBase64String(clientResponse.Id));
                if (user is null)
                {
                    return new JsonResult(new AssertionVerificationResult { Status = "error", ErrorMessage = "invalid Credential" });
                }

                await signInManager.SignInAsync(user, false);

                var credential = JsonConvert.DeserializeObject<StoredCredential>(user.PasswordlessPublicKey);

                var result = await fido2.MakeAssertionAsync(clientResponse, options, credential.PublicKey, credential.SignatureCounter,
                    (credentialIdUserHandleParams, cancellationToken) => Task.FromResult(credential.UserHandle.SequenceEqual(credentialIdUserHandleParams.UserHandle)));

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName)
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

                return new JsonResult(result);
            }
            catch (Exception exc)
            {
                return new JsonResult(new AssertionVerificationResult { Status = "error", ErrorMessage = exc.Message });
            }
        }

        public async Task<IActionResult> OnPostSignInOptionsAsync([FromForm] string username)
        {
            try
            {
                var user = await signInManager.UserManager.FindByNameAsync(username) ?? throw new ArgumentException("Username was not registered");
                var credential = JsonConvert.DeserializeObject<StoredCredential>(user.PasswordlessPublicKey);

                var options = fido2.GetAssertionOptions(new List<PublicKeyCredentialDescriptor> { credential.Descriptor }, UserVerificationRequirement.Discouraged);

                HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

                return new JsonResult(options);
            }

            catch (Exception exc)
            {
                return new JsonResult(new AssertionOptions { Status = "error", ErrorMessage = exc.Message });
            }
        }

        public class InputModel
        {
            [Required]
            [Display(Name = "Username")]
            public string Username { get; set; }

            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }
    }
}
