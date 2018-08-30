using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Clients.ActiveDirectory; 
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage.Blob;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace BlobStorageUploadExample.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        public IConfiguration Configuration { get; }
        public string Message { get; set; }

        public IndexModel(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void OnGet()
        {
        }

        [HttpPost]
        public async Task<IActionResult> OnPostUploadFilesAsync(List<IFormFile> files)
        {
            CloudBlobContainer blobContainer = new CloudBlobContainer(new Uri("https://dummystorageaccountname.blob.core.windows.net"));

            string authenticationMethod = Configuration["StorageAccountInfo:AuthenticationMethod"];

            if (authenticationMethod == "StorageAccountKey") // Storage Account Key
            {

                StorageCredentials storageCredentials =
                    new StorageCredentials(Configuration["StorageAccountInfo:StorageAccountName"],
                    Configuration["StorageAccountInfo:StorageAccountKey"]);

                CloudStorageAccount storageAccount = new CloudStorageAccount(storageCredentials, true);
                CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();
                blobContainer = blobClient.GetContainerReference(Configuration["StorageAccountInfo:StorageAccountContainerName"]);

            }
            else if (authenticationMethod == "SASToken") // Shared Access Signature
            {
                var storageAccountUrlwithSASToken =
                    "https://" 
                    + Configuration["StorageAccountInfo:StorageAccountName"]
                    + ".blob.core.windows.net/"
                    + Configuration["StorageAccountInfo:StorageAccountContainerName"]
                    + Configuration["StorageAccountInfo:SharedAccessSignature"];

                blobContainer = new CloudBlobContainer(new Uri(storageAccountUrlwithSASToken));

            }
            else if (authenticationMethod == "AzureAD") // AzureAD Service Principal (app) Authentication
            {
                var accessToken = await GetUserOAuthToken();

                var storageAccountUrl = 
                    "https://" 
                    + Configuration["StorageAccountInfo:StorageAccountName"] 
                    + ".blob.core.windows.net/" 
                    + Configuration["StorageAccountInfo:StorageAccountContainerName"];

                // Use the access token to create the storage credentials.
                TokenCredential tokenCredential = new TokenCredential(accessToken.AccessToken);
                StorageCredentials storageCredentials = new StorageCredentials(tokenCredential);
                StorageUri storageUri = new StorageUri(new Uri(storageAccountUrl));
                blobContainer = new CloudBlobContainer(storageUri, storageCredentials);

            }


            long size = files.Sum(f => f.Length);

            // full path to file in temp location (buffer file locally before uploading).
            // note: for larger files and workloads, consider streaming instead.
            var filePath = Path.GetTempFileName();

            int uploadFileCount = 0;

            foreach (var formFile in files)
            {
                if (formFile.Length > 0)
                {
                    // create a local reference to a blob
                    CloudBlockBlob blockBlob = blobContainer.GetBlockBlobReference(Path.GetFileName(formFile.FileName));
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        // upload the blob to Azure Storage
                        await blockBlob.UploadFromStreamAsync(stream);
                        uploadFileCount++;
                    }
                }
            }

            Message = "Number of files uploaded to Azure Storage: " + uploadFileCount;
            return Page();

        }

        private async Task<AuthenticationResult> GetUserOAuthToken()
        {
            string resourceId = "https://storage.azure.com/";
            string authority = "https://login.microsoftonline.com/" + Configuration["AzureAd:TenantId"] + "/oauth2/token";

            string clientId = Configuration["AzureAd:ClientId"];
            string clientSecret = Configuration["StorageAccountInfo:AzureAD_ClientSecret"]; ;

            // Construct the authority string from the Azure AD OAuth endpoint and the tenant ID. 
            AuthenticationContext authContext = new AuthenticationContext(authority);

            // Acquire an access token from Azure AD. 
            var clientCredential = new ClientCredential(clientId, clientSecret);
            AuthenticationContext context = new AuthenticationContext(authority, false);
            AuthenticationResult authenticationResult = await context.AcquireTokenAsync(resourceId, clientCredential);

            return authenticationResult;

        }
    }
}
