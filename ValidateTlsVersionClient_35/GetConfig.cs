using Microsoft.Win32;
using System;


namespace ValidateTlsVersion
{
    // Reads the AppConfig and registry keys
    class GetConfig
    {
        public bool SchUseStrongCrypto { get; internal set; }
        public int SystemDefaultTlsVersions { get; internal set; }
        public void GetRegistry(bool verbose)
        {
            //GetRegistry(@"Wow6432Node\", @"v2.0.50727");
            GetRegistry(verbose, @"Wow6432Node\", @"v4.0.30319");

            //GetRegistry("", "v2.0.50727");
            //GetRegistry("", "v4.0.30319");
        }

        private void GetRegistry(bool verbose, string wow, string version)
        {
            using (RegistryKey rk = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\{wow}Microsoft\.NETFramework\{version}"))
            {
                object schUseStrongCryptoValue = rk.GetValue("SchUseStrongCrypto");
                if (verbose) Console.WriteLine($"NOTE: SchUseStrongCrypto={schUseStrongCryptoValue}");
                if (schUseStrongCryptoValue == null) SchUseStrongCrypto = true;
                else SchUseStrongCrypto = (Int32)schUseStrongCryptoValue == 0 ? false : true;

                object systemDefaultTlsVersionsValue = rk.GetValue("SystemDefaultTlsVersions");
                if (verbose) Console.WriteLine($"NOTE: SystemDefaultTlsVersions={systemDefaultTlsVersionsValue}");
                if (systemDefaultTlsVersionsValue == null) SystemDefaultTlsVersions = 0;
                else systemDefaultTlsVersionsValue = (Int32)SystemDefaultTlsVersions;
            }
        }
    }
}
