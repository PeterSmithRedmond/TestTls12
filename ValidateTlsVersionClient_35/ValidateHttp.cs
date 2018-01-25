using System;
using System.IO;
using System.Linq;
using System.Net;
using static ValidateTlsVersion.ValidateSslAuthentication;

namespace ValidateTlsVersion
{
    class ValidateHttp
    {
        public static int ValidateHttpWebRequest(string server, int port, bool verbose, System.Security.Authentication.SslProtocols sslProtocols, string expected, out string actual)
        {
            var url = new Uri($"https://{server}:{port}/");
            if (verbose) Console.WriteLine($"STARTING {server} protocol {sslProtocols}");
            actual = "FAIL_NOT_SET!";

            ServicePointManager.DefaultConnectionLimit = 1;
            var startingProtocol = ServicePointManager.SecurityProtocol;
            if (sslProtocols != SslProtocolsExtensions.DontPassAnything)
            {
                // DontPassAnything really means don't set any value at all.
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)sslProtocols;
            }
            var sp = ServicePointManager.FindServicePoint(url);
            if (sp != null)
            {
                // Kill the old service point. Since in practice we only ever do a single test,
                // there shouldn't ever be an old service point and this code should never
                // be called.
                sp.ConnectionLimit = 1;
                sp.MaxIdleTime = 0;
                int nopen = sp.CurrentConnections;
            }
            ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, change, policyerorrs) =>
            {
                // Always accept the certificate. This is only OK because 
                // we're doing a test. In real code, accepting all certificates
                // is a terrible idea and causes security violations.
                return true;
            };

            string step = "Starting";
            try
            {
                step = "Make WebRequest";
                var req = WebRequest.Create(url);
                step = "Get Response";
                WebResponse response = null;
                try
                {
                    response = req.GetResponse();
                }
                catch (Exception ex)
                {
                    var we = ex as WebException;
                    if (we != null && we.Status == WebExceptionStatus.SecureChannelFailure)
                    {
                        actual = "FAILED_TLS";
                    }
                    else
                    {
                        actual = $"FAIL_EXCEPTION_AT_GET_{ex.Message}";
                    }
                }
                if (response != null)
                {
                    var reader = new StreamReader(response.GetResponseStream());
                    var data = reader.ReadToEnd();
                    var dataitems = data.Split(new char[] { ' ' });
                    actual = dataitems[0];
                }
                step = "Close";
                step = "Done";
            }
            catch (Exception ex)
            {
                if (verbose) Console.WriteLine($"EXCEPTION at {step}: {ex.Message}");
                actual = $"FAIL_EXCEPTION_AT{step}_{ex.Message}";
            }

            int Retval = 0;
            if (actual != expected && expected != Program.ExpectWasNotSet)
            {
                Retval = 1;
            }
            return Retval;
        }
    }
}
