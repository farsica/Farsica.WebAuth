using Farsica.WebAuth.Data;
using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;

namespace Farsica.WebAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly IFido2 fido2;
        private readonly ApplicationDbContext context;

        public AccountController(SignInManager<ApplicationUser> signInManager, IFido2 fido2, ApplicationDbContext context)
        {
            this.signInManager = signInManager;
            this.fido2 = fido2;
            this.context = context;
        }

        [HttpPost]
        [Route("[action]")]
        public async Task<IActionResult> Login(AuthenticatorAssertionRawResponse request)
        {
            try
            {
                var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
                var options = AssertionOptions.FromJson(jsonOptions);

                var user = await context.Users.FirstOrDefaultAsync(t => t.CredentialId == Convert.ToBase64String(request.Id));
                if (user is null)
                {
                    return new JsonResult(new AssertionVerificationResult { Status = "error", ErrorMessage = "invalid Credential" });
                }

                await signInManager.SignInAsync(user, false);

                var credential = System.Text.Json.JsonSerializer.Deserialize<StoredCredential>(user.PasswordlessPublicKey);

                var result = await fido2.MakeAssertionAsync(request, options, credential.PublicKey, credential.SignatureCounter,
                    (credentialIdUserHandleParams, cancellationToken) => Task.FromResult(credential.UserHandle.SequenceEqual(credentialIdUserHandleParams.UserHandle)));

                return Ok(result);
            }
            catch (Exception exc)
            {
                return Ok(new AssertionVerificationResult { Status = "error", ErrorMessage = exc.Message });
            }
        }

        [HttpPost]
        [Route("[action]")]
        public async Task<IActionResult> LoginOptions(LoginViewModel request)
        {
            try
            {
                var user = await signInManager.UserManager.FindByNameAsync(request.Username) ?? throw new ArgumentException("Username was not registered");
                var credential = System.Text.Json.JsonSerializer.Deserialize<StoredCredential>(user.PasswordlessPublicKey);

                var options = fido2.GetAssertionOptions(new List<PublicKeyCredentialDescriptor> { credential.Descriptor }, UserVerificationRequirement.Discouraged);

                HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

                return Ok(options);
            }

            catch (Exception exc)
            {
                return Ok(new AssertionOptions { Status = "error", ErrorMessage = exc.Message });
            }
        }

        [HttpPost]
        [Route("[action]")]
        public IActionResult RegisterOptions(RegisterViewModel request)
        {
            var user = new Fido2User
            {
                Id = Encoding.UTF8.GetBytes(request.Username),
                Name = request.Username,
                DisplayName = $"{request.FirstName} {request.LastName}",
            };

            var options = fido2.RequestNewCredential(user, new List<PublicKeyCredentialDescriptor>());
            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            return Ok(options);
        }

        [HttpPost]
        [Route("[action]")]
        public async Task<IActionResult> Register(AuthenticatorAttestationRawResponse attestationResponse)
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
                    PasswordlessPublicKey = System.Text.Json.JsonSerializer.Serialize(storedCredential),
                };
                await signInManager.UserManager.SetUserNameAsync(user, options.User.Name);
                var result = await signInManager.UserManager.CreateAsync(user);

                return Ok(result.Succeeded ? fidoCredentials : new Fido2.CredentialMakeResult("error", string.Join(",", result.Errors.Select(t => t.Description)), null));
            }
            catch (Exception exc)
            {
                return Ok(new Fido2.CredentialMakeResult("error", exc.Message, null));
            }
        }

        private async Task<bool> IsCredentialUnique(IsCredentialIdUniqueToUserParams userParams, CancellationToken cancellationToken)
        {
            return !await context.Users.AnyAsync(t => t.CredentialId == Convert.ToBase64String(userParams.CredentialId), cancellationToken: cancellationToken);
        }

    }
}