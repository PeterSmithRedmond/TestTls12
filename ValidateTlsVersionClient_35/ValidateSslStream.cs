using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;


namespace ValidateTlsVersion
{
    public class ValidateSslAuthentication
    {
        public static int ValidateSslStream(string host, int port, bool verbose, System.Security.Authentication.SslProtocols sslProtocols, string expected, out string actual)
        {
            var certificateHostName = "supersimplesockettlsversionserver.example.com";

            if (verbose) Console.WriteLine($"STARTING {host} protocol {sslProtocols}");
            actual = "FAIL_NOT_SET!";

            string step = "Starting";
            try
            {
                step = "Make TcpClient";
                var tcpclient = new TcpClient(host, port);
                tcpclient.NoDelay = true;
                step = "Get Stream";
                var networkStream = tcpclient.GetStream();
                Stream stream = networkStream;
                SslProtocols actualProtocol = SslProtocols.Ssl2; // Ssl2 is our default for "not set" :-)
                string actualProtocolString = "Ssl2"; // Still the default for "not set"

                step = "Make SslStream";
                var sslstream = new SslStream(networkStream, false, (sender, cert, chain, errors) => { return true; });
                stream = sslstream;
                step = "AuthenticateAsClient";
                try
                {
                    if (sslProtocols == SslProtocolsExtensions.DontPassAnything) 
                    {
                        step = "AuthenticateAsClient_default";
                        sslstream.AuthenticateAsClient(certificateHostName);
                    }
                    else
                    {
                        step = "AuthenticateAsClient_param";
                        sslstream.AuthenticateAsClient(certificateHostName, null, sslProtocols, false);
                    }
                    step = "AuthenticateAsClient_set_actualProtocol";
                    actualProtocol = sslstream.SslProtocol;
                    step = "AuthenticateAsClient_set_actualProtocolString";
                    actualProtocolString = SslProtocolsExtensions.ToString(actualProtocol);
                }
                catch (Exception ex2)
                {
                    if (ex2.Message == "The client and server cannot communicate, because they do not possess a common algorithm")
                    {
                        actual = "FAILED_TLS";
                    }
                    else
                    {
                        actual = $"FAIL_EXCEPTION_AT_{step}_{ex2.Message}";
                    }
                    if (verbose) Console.WriteLine($"EXCEPTION: when authenticateAsClient got {ex2.Message}");
                    tcpclient.Close();
                }

                if (tcpclient.Connected)
                {
                    step = "Store";

                    var request = "biggely /index.html\r\n";
                    var requestBuffer = System.Text.Encoding.ASCII.GetBytes(request);

                    if (verbose) Console.WriteLine($"WRITE STRING {request}");
                    stream.Write(requestBuffer, 0, requestBuffer.Length);

                    if (verbose) Console.WriteLine($"READ STRING");
                    byte[] buffer = new byte[1024];
                    int i;
                    string data = "";
                    while ((i = stream.Read(buffer, 0, buffer.Length)) != 0)
                    {
                        data = data + System.Text.Encoding.ASCII.GetString(buffer, 0, i);
                        if (verbose) Console.WriteLine($"GOT PARTIAL STRING: {data}");
                    }
                    if (verbose) Console.WriteLine($"GOT COMPLETE STRING: {data}");
                    // $"HTTP/1.0 200 OK\r\n\r\n{replyword} SuperSimpleSocketTlsVersionServer TLS {protocols.ToString()}"
                    var lines = data.Split(new char[] { '\n' });
                    var dataitems = lines[lines.Length-1].Split(new char[] { ' ' });
                    actual = dataitems[0];

                    if (actual != actualProtocolString)
                    {
                        actual = $"{actual} OR {SslProtocolsExtensions.ToString(actualProtocol)}";
                        Console.WriteLine($"ERROR: What? at {step} the measured protocol is {actualProtocol} but the server reported {actual}");
                    }
                }

                step = "Close";
                tcpclient.Close();
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


        //
        // Summary:
        //     Verifies the remote Secure Sockets Layer (SSL) certificate used for authentication.
        //
        // Parameters:
        //   sender:
        //     An object that contains state information for this validation.
        //
        //   certificate:
        //     The certificate used to authenticate the remote party.
        //
        //   chain:
        //     The chain of certificate authorities associated with the remote certificate.
        //
        //   sslPolicyErrors:
        //     One or more errors associated with the remote certificate.
        //
        // Returns:
        //     A System.Boolean value that determines whether the specified certificate is accepted
        //     for authentication.
        //public delegate bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors);

    }
}
