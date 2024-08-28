//-----------------------------------------------------------------------
// <copyright file="Verify_FunctionalAccount_Credentials_Action.cs" company="integrations@beyondtrust.com">
// Copyright (c) integrations@beyondtrust.com. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Composition;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using PasswordServices.Plugins.Abstractions;
using PasswordServices.Plugins.Abstractions.Enumerations;
using PasswordServices.Plugins.Abstractions.Exceptions;
using PasswordServices.Plugins.Abstractions.Models;
using System.Net.Http.Json;

namespace PasswordSafe.PlatformPlugin.SailPoint_Custom_Plugin
{

    /// <summary>
    /// This class is responsible for Verify_FunctionalAccount_Credentials action.
    /// </summary>
    [Export("Verify_FunctionalAccount_Credentials")]
    public class Verify_FunctionalAccount_Credentials_Action : PluginActionBase
    {
        // Custom Code - START
        private static async Task<string> GetTokenAsync(string APIURL, string CLIENT_ID, string CLIENT_SECRET)
        {
            try
            {
                var httpClient = new HttpClient();
                //Post body content
                string body = "grant_type=client_credentials&client_id=" + CLIENT_ID + "&client_secret=" + CLIENT_SECRET;
                StringContent postData = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");
                HttpResponseMessage message = httpClient.PostAsync(APIURL + "/oauth/token",postData).Result;
                string result = await message.Content.ReadAsStringAsync();
                if (message.IsSuccessStatusCode)
                {
                    return result;
                }
                else
                {
                    throw new Exception("Failed to Authenticate with Functional Account Credentials " + result);
                }
            }
            catch (Exception ex)
            {
                Console.Write("####### Error in method = " + ex.ToString());
                throw new Exception("Failed to Authenticate with Functional Account Credentials " + ex.ToString());
            }
        }
        // Custom Code - END

        private const EPluginActionType SupportedActionType = EPluginActionType.Verify_FunctionalAccount_Credentials;


        /// <summary>
        /// Initializes a new instance of the <see cref="Verify_FunctionalAccount_Credentials_Action"/> class.
        /// </summary>
        [ImportingConstructor]
        public Verify_FunctionalAccount_Credentials_Action()
        {  }

        /// <inheritdoc/>
        public override bool IsMatch(EPluginActionType actionType)
        {
            return actionType == SupportedActionType;
        }

        /// <inheritdoc/>
        public override PluginActionDetails GetActionDetails()
        {
            var requiredArgs = new PluginActionDetails(SupportedActionType, true);

            requiredArgs.RequiredParameters.Add(EActionParameter.ManagedSystem_HostsByOption);  // string[]
            requiredArgs.RequiredParameters.Add(EActionParameter.ManagedSystem_Port);  // int?
            requiredArgs.RequiredParameters.Add(EActionParameter.ManagedSystem_Timeout);   // int?


            // Uncomment required parameters below
            // --- Functional Account parameters
             requiredArgs.RequiredParameters.Add(EActionParameter.FunctionalAccount_AccountName_only);             // string
             requiredArgs.RequiredParameters.Add(EActionParameter.FunctionalAccount_CredentialsCurrent_Password);  // string
            // requiredArgs.RequiredParameters.Add(EActionParameter.FunctionalAccount_CredentialsNew_Password);      // string
            // --- Managed Account parameters
            // requiredArgs.RequiredParameters.Add(EActionParameter.ManagedAccount_AccountName_only);                // string
            // requiredArgs.RequiredParameters.Add(EActionParameter.ManagedAccount_CredentialsCurrent_Password);     // string
            // requiredArgs.RequiredParameters.Add(EActionParameter.ManagedAccount_CredentialsNew_Password);         // string

            return requiredArgs;
        }

        /// <inheritdoc/>
        public override PluginActionResult ExecuteAction(ActionParameters parameters)
        {
            var pluginActionResult = new PluginActionResult(parameters);
            
            try
            {
                if (parameters.ActionType != SupportedActionType)
                {
                    pluginActionResult.FinishAction(
                        EPluginActionResult.NotSupported,
                        EPluginActionErrorCode.WrongParameters,
                        $"Action '{SupportedActionType}' does not process '{parameters.ActionType}'");
                    return pluginActionResult;
                }
                var paramFactory = new ParameterFactory(parameters);

                // Uncomment required parameters below
                // --- Functional Account parameters
                 string functionalAccountName = paramFactory.Get_String_Value(EActionParameter.FunctionalAccount_AccountName_only, true, GlobalConstants.ParameterError_FunctionalAccountNameIsEmptyString);
                 string currentPasswordFA = paramFactory.Get_String_Value(EActionParameter.FunctionalAccount_CredentialsCurrent_Password, true, GlobalConstants.ParameterError_FunctionalAccountCurrentPasswordIsNotDefined);
                // string newPasswordFA = paramFactory.Get_String_Value(EActionParameter.FunctionalAccount_CredentialsNew_Password, true, GlobalConstants.ParameterError_FunctionalAccountNewPasswordIsNotDefined);
                // --- Managed Account parameters
                // string managedAccountName = paramFactory.Get_String_Value(EActionParameter.ManagedAccount_AccountName_only, true, GlobalConstants.ParameterError_ManagedAccountNameIsEmptyString);
                // string currentPasswordMA = paramFactory.Get_String_Value(EActionParameter.ManagedAccount_CredentialsCurrent_Password, true, GlobalConstants.ParameterError_ManagedAccountCurrentPasswordIsNotDefined);
                // string newPasswordMA = paramFactory.Get_String_Value(EActionParameter.ManagedAccount_CredentialsNew_Password, true, GlobalConstants.ParameterError_ManagedAccountNewPasswordIsNotDefined);


                // --- Hosts
                string[] hosts = paramFactory.Get_HostsByOptions_Value();

                int portNumber = paramFactory.Get_Port_Parameter(ParameterFactory.DefaultPort);
                int timeout = paramFactory.Get_Timeout_Parameter(ParameterFactory.DefaultConnectionTimeout);

                foreach (string host in hosts)
                {
                    if (pluginActionResult.IsFinished && pluginActionResult.Result == EPluginActionResult.Success) break;
                    else if (pluginActionResult.IsFinished)
                    {
                        pluginActionResult = new PluginActionResult(pluginActionResult);
                    }
                   
                    pluginActionResult.Dump = $"Verify_FunctionalAccount_Credentials action on SailPoint Custom Plugin system: Server={host}:{portNumber}";

                    // Custom Code - START
                    try
                    {
                        // Extract Functional Account Cliend ID and Secret
                        string[] fa_auth = currentPasswordFA.Split(':');
                        string fa_client_id = fa_auth[0];
                        string fa_client_secret = fa_auth[1];
                        var accessToken = Task.Run(async () => await GetTokenAsync(host, fa_client_id, fa_client_secret)).Result;
                        dynamic jsonString_token = JsonConvert.DeserializeObject(accessToken);
                        string access_token = jsonString_token.access_token;
                        pluginActionResult.FinishAction(EPluginActionResult.Success, EPluginActionErrorCode.NoError, "Functional Account credentials tested successfully");  // success
                    }
                    catch (Exception ex)
                    {
                        pluginActionResult.Dump = ex.Message; // or your message
                        pluginActionResult.FinishAction(EPluginActionResult.Failed, EPluginActionErrorCode.SomeErrors, "Functional Account credentials verification failed: " + ex.Message);  // failed with exception     
                    }

                    // Custom Code - END
                    // Add your code in this place and remove NotImplementedException below.
                    // Completed action must set a status of the PluginActionResult object by calling method FinishAction(<EPluginActionResult>,<EPluginActionErrorCode>,<string>) with proper arguments.
                    //       Samples of the action results: ;
                    //            pluginActionResult.FinishAction(EPluginActionResult.Success, EPluginActionErrorCode.NoError, "<Your message>");  // success
                    //             or
                    //            pluginActionResult.FinishAction(EPluginActionResult.Failed, EPluginActionErrorCode.AuthenticationFailed, "<Your message>");  // failed  with authentication error code
                    //             or 
                    //            pluginActionResult.FinishAction(EPluginActionResult.Failed, EPluginActionErrorCode.Timeout, "Communication timeout");  // failed because of timeout
                    //
                    // To add one or more informational messages to the action result set Dump property with a new message: 
                    //            pluginActionResult.Dump="your message"; 
                    // 
                    // DiscoveryAccounts action must return list of discovered accounts in PluginActionResult object. 
                    // Add new record to the PluginActionResult's property OutputData with Key=OutputDataKey.DiscoveredAccounts and Value=<list of discovered accounts names>.  
                    //       Sample of code: 
                    //            List<string> discoveredAccounts = new List<string>();
                    //            .......your code to discover accounts.....
                    //            pluginActionResult.FinishAction(EPluginActionResult.Success, EPluginActionErrorCode.NoError, $"{discoveredAccounts.Count} accounts were discovered");
                    //            pluginActionResult.OutputData.Add(OutputDataKey.DiscoveredAccounts, discoveredAccounts);

                    // COMMENTED throw new NotImplementedException("Missing implementation code in the class Verify_FunctionalAccount_Credentials_Action");

                }
            }
            catch (NotImplementedException ex)
            {
                pluginActionResult.Dump = $"NotImplementedException: {ex.Message}";
                pluginActionResult.FinishAction(
                        EPluginActionResult.Terminated,
                        EPluginActionErrorCode.Exception,
                        GlobalConstants.ActionFailedSeeLog
                        );
            }
            catch (WrongParameterException ex)
            {
                pluginActionResult.Dump = $"Parameter error: {ex.Message}";
                pluginActionResult.FinishAction(
                        EPluginActionResult.Terminated,
                        EPluginActionErrorCode.WrongParameters,
                        GlobalConstants.ActionFailedSeeLog
                        );
            }
            catch (Exception ex)
            {
                pluginActionResult.Dump = $"Exception: {ex.Message}";
                pluginActionResult.FinishAction(
                        EPluginActionResult.Terminated,
                        EPluginActionErrorCode.Exception,
                        GlobalConstants.ActionFailedSeeLog
                        );
            }
            finally
            {
                if (!pluginActionResult.IsFinished)
                {
                    string message = $"Action has not been finished. Result={pluginActionResult?.Result}";
                    pluginActionResult.FinishAction(EPluginActionResult.Unknown, EPluginActionErrorCode.Exception, message);
                }
            }
            return pluginActionResult;
        }
    }
}
