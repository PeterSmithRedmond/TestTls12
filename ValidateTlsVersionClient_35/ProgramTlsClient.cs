using System;
using System.Security.Authentication;

namespace ValidateTlsVersion
{
    public static class SslProtocolsExtensions
    {
        public const SslProtocols DontPassAnything = (SslProtocols)0x11118888;
        public const SslProtocols Tls12 = (SslProtocols)0x00000C00;
        public const SslProtocols Tls11 = (SslProtocols)0x00000300;
        public static string ToString(SslProtocols value)
        {
            if (value == DontPassAnything) return "DontPassAnything";
            if (value == Tls12) return "Tls12";
            if (value == Tls11) return "Tls11s";
            return value.ToString();
        }
    }

    class Program
    {
        public const string ExpectWasNotSet = "ExpectWasNotSet";
        static int Main(string[] args)
        {
            string api = "socket";
            string server = "169.254.201.47"; // Common address for server (running on .NET 47)
            int port = 13342; // TLS12_ON_13342
            var protocols = SslProtocols.Ssl2; // Out default for "not a real protocol"
            string expect = ExpectWasNotSet;
            bool waitForRead = false;
            bool verbose = false;
            bool parseOk = true;


            for (int i=0; i<args.Length; i++)
            {
                var argarg = (i < args.Length - 1) ? args[i + 1] : "";
                switch (args[i])
                {
                    case "-api":
                        switch (argarg)
                        {
                            case "socket": api = argarg; break;
                            case "http": api = argarg; break;
                            default:
                                Console.WriteLine($"ERROR: -arg {argarg} expected either socket or http");
                                parseOk = false;
                                break;
                        }
                        i += 1;
                        break;
                    case "-expect":
                        {
                            if (argarg == "")
                            {
                                Console.WriteLine($"ERROR: -expect {argarg} expected e.g. Tls12");
                                parseOk = false;
                            }
                            else
                            {
                                expect = argarg;
                            }
                        }
                        i += 1;
                        break;
                    case "-port":
                        {
                            var parsePort = Int32.TryParse(argarg, out port);
                            if (!parsePort)
                            {
                                Console.WriteLine($"ERROR: -port {argarg} expected e.g. 13400");
                                parseOk = false;
                            }
                        }
                        i += 1;
                        break;
                    case "-quiet":
                        verbose = false ;
                        break;
                    case "-server":
                        {
                            if (argarg == "")
                            {
                                Console.WriteLine($"ERROR: -server {argarg} expected e.g. localhost");
                                parseOk = false;
                            }
                            else
                            {
                                server = argarg;
                            }
                        }
                        i += 1;
                        break;
                    case "-tls":
                        {
                            var tlsvalues = argarg.Split(new char[] { '+' });
                            protocols = 0;
                            foreach (var item in tlsvalues)
                            {
                                switch (item)
                                {
                                    case "DontPassAnything": protocols |= SslProtocolsExtensions.DontPassAnything; break;
                                    case "SystemDefault": protocols = 0; break; 
                                    case "None": protocols = 0; break; 
                                    case "Ssl3": protocols |= SslProtocols.Ssl3; break;
                                    case "Tls": protocols |= SslProtocols.Tls; break;
                                    case "Tls10": protocols |= SslProtocols.Tls; break;
                                    case "Tls11": protocols |= SslProtocolsExtensions.Tls11; break;
                                    case "Tls12": protocols |= SslProtocolsExtensions.Tls12; break;
                                    case "Default": protocols |= SslProtocols.Default; break;
                                    default:
                                        Console.WriteLine($"ERROR: -tls {item} exected None+SystemDefault+DontPassAnything+Ssl3+Tls+Tls11+Tls12+Default");
                                        parseOk = false;
                                        break;
                                }
                            }
                        }
                        i += 1;
                        break;
                    case "-verbose":
                        verbose = true;
                        break;
                    case "-waitforread":
                        waitForRead = true;
                        break;
                    default:
                        Console.WriteLine($"ERROR: {args[i]} is invalid argument");
                        parseOk = false;
                        break;
                }
            }

            string actual = "FAIL_REALLY_NOT_SET!";
            int result = 0;
            if (!parseOk)
            {
                result = 2;
            }
            else
            {
                //Note: the config will print out information when -verbose is on.
                //That's the only actual effect of the registry value.
                var config = new GetConfig();
                config.GetRegistry(verbose); 
                switch (api)
                {
                    case "http": result = ValidateHttp.ValidateHttpWebRequest(server, port, verbose, protocols, expect, out actual); break;
                    case "socket": result = ValidateSslAuthentication.ValidateSslStream(server, port, verbose, protocols, expect, out actual); break;
                }
            }
            if (expect == ExpectWasNotSet)
            {
                // If there are no expectations then we aren't either passing or failing.
                Console.WriteLine($"RESULT: actual {actual} -tls {SslProtocolsExtensions.ToString(protocols)} -port {port}");
            }
            else if (result == 0)
            {
                Console.WriteLine($"PASS: expected {expect}");
            }
            else
            {
                Console.WriteLine($"FAIL: expected {expect} actual {actual} -tls {SslProtocolsExtensions.ToString(protocols)} -port {port}");
            }

            if (waitForRead)
            {
                Console.WriteLine("Press RETURN to exit");
                Console.ReadLine();
            }
            return result;
        }
    }
}
