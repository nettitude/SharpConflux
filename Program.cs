using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using System.IO;
using System.Web;
using System.Collections.Generic;

namespace SharpConflux
{
    internal class Program
    {
        public static void PrintUsage()
        {
            string help = "";
            help += "[*] Usage: SharpConflux.exe <Arguments>\r\n";
            help += "[*] Core Arguments:\r\n";
            help += "    /url      :  Confluence URL (e.g. https://my-confluence-instance.atlassian.net)\r\n";
            help += "    /ua       :  User-Agent string to use. Default: \"Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko\"\r\n";
            help += "    /help     :  Show help message\r\n";
            help += "[*] Confluence Type Arguments:\r\n";
            help += "    /cloud    :  Confluence Cloud version hosted in https://clientsubdomain.atlassian.net\r\n";
            help += "    /onprem   :  Confluence Server / Data Center version, typically hosted on-premise (e.g. http://confluenceinstance.internal.local:8090)\r\n";
            help += "[*] Authentication Arguments:\r\n";
            help += "    /user     :  Username / email adress to authenticate with\r\n";
            help += "    /pwd      :  Password associated to the specified username. Only supported for Confluence Server / Data Center instances\r\n";
            help += "    /basic    :  If toggled, username + password will use Basic authentication. Only supported for Confluence Server / Data Center instances\r\n";
            help += "    /form     :  If toogled, username + password authentication will be performed through form data. Only supported for Confluence Server / Data Center instances\r\n";
            help += "    /apitoken :  API token associated to the specified username. Only supported for Confluence Cloud instances\r\n";
            help += "    /pat      :  Personal Access Token (PAT) for username-less authentication. Only supported for Confluence Server / Data Center instances\r\n";
            help += "    /cookies  :  Session cookie(s) for username-less authentication. For Confluence Cloud, typically providing \"tenant.session.token\" or \"cloud.session.token\" is sufficient. For Confluence Server / Data Center, typically \"JSESSIONID\" or \"seraph.confluence\" is sufficient\r\n";
            help += "[*] Action Arguments:\r\n";
            help += "    /spaces   :  List available spaces\r\n";
            help += "    /query    :  String to search for (e.g. password)\r\n";
            help += "    /cql      :  Manual CQL query (e.g. \"(type=page OR type=blogpost) AND (title ~ Password OR text ~ Password)\" )\r\n";
            help += "    /limit    :  Limit the number of results. Default: 10\r\n";
            help += "    /view     :  View the source code of the specified page ID\r\n";
            help += "    /pretty   :  If toggled, the returned HTML source code will have HTML tags removed for easier reading\r\n";
            help += "    /download :  Download an attachment by its ID\r\n";
            help += "    /b64      :  If toggled, the downloaded attachment will be displayed as a large base64-encoded string instead of being dropped to disk\r\n";
            help += "    /upload   :  Upload an attachment to the specified page ID\r\n";
            help += "    /path     :  File system path used when saving an attachment to disk (default: filename of the attachment in the current working directory) and when uploading an attachment\r\n";
            Console.WriteLine(help);
        }

        static CookieContainer cookieContainer = new CookieContainer();
        static HttpClientHandler handler = new HttpClientHandler() { CookieContainer = cookieContainer };
        static HttpClient client = new HttpClient(handler);

        static void Main(string[] args)
        {
            var options = new Options();
            if (options.ParseArguments(args))
            {
                if (options.help)
                {
                    PrintUsage();
                    return;
                }
                if (args.Length < 4)
                {
                    Console.WriteLine("[-] An insufficient number of arguments has been provided");
                    PrintUsage();
                    return;
                }

                // Mandatory arguments
                if (string.IsNullOrEmpty(options.url))
                {
                    Console.WriteLine("[-] No Confluence URL has been provided");
                    return;
                }
                if (!options.cloud && !options.onprem)
                {
                    Console.WriteLine("[-] No Confluence type has been provided");
                    return;
                }
                else if (options.cloud && options.onprem)
                {
                    Console.WriteLine("[-] The provided Confluence type is incorrect");
                    return;
                }

                // Authentication argument checks
                if (options.cloud && !string.IsNullOrEmpty(options.pwd))
                {
                    Console.WriteLine("[-] Username + password authentication is not supported for Confluence Cloud instances");
                    return;
                }
                if (options.cloud && !string.IsNullOrEmpty(options.pat))
                {
                    Console.WriteLine("[-] Personal Access Token (PAT) authentication is not supported for Confluence Cloud instances");
                    return;
                }
                if (options.onprem && !string.IsNullOrEmpty(options.apitoken))
                {
                    Console.WriteLine("[-] Username + API token authentication is not supported for Confluence Server / Data Center instances");
                    return;
                }
                if (!string.IsNullOrEmpty(options.pat) && !string.IsNullOrEmpty(options.user))
                {
                    Console.WriteLine("[!] Personal Access Token (PAT) authentication does not require an username to be specified");
                }
                if (!string.IsNullOrEmpty(options.cookies) && !string.IsNullOrEmpty(options.user))
                {
                    Console.WriteLine("[!] Cookie-based authentication does not require an username to be specified");
                }
                if ((!string.IsNullOrEmpty(options.pwd) && string.IsNullOrEmpty(options.user)) || (!string.IsNullOrEmpty(options.apitoken) && string.IsNullOrEmpty(options.user)))
                {
                    Console.WriteLine("[-] A username is required for this authentication method");
                    return;
                }
                if (options.basic && options.form)
                {
                    Console.WriteLine("[-] The provided authentication type is incorrect");
                    return;
                }
                if (!string.IsNullOrEmpty(options.pwd) && !string.IsNullOrEmpty(options.user))
                {
                    if (!options.basic && !options.form)
                    {
                        Console.WriteLine("[-] Username + password authentication requires either /basic or /form to be toggled");
                        return;
                    }
                }

                // Optional arguments
                if (!string.IsNullOrEmpty(options.query))
                {
                    if (Connect(options.url, options.ua, options.user, options.pwd, options.apitoken, options.pat, options.cookies, options.basic, options.form))
                    {
                        Console.WriteLine($"[+] Searching for pages matching: {options.query}");
                        if (options.cloud)
                        {
                            // API endpoint used to search for pages
                            string searchEndpoint = options.url + "/wiki/rest/api/content/search?limit=" + options.limit + "&expand=version&cql=(type=page%20OR%20type=blogpost)%20AND%20text%20~%20%22{0}%22";
                            SearchPages(options.query, searchEndpoint, "cloud");
                        }
                        else
                        {
                            // API endpoint used to search for pages
                            string searchEndpoint = options.url + "/rest/api/content/search?limit=" + options.limit + "&expand=version&cql=(type=page%20OR%20type=blogpost)%20AND%20text%20~%20%22{0}%22";
                            SearchPages(options.query, searchEndpoint, "onprem");
                        }

                        Console.WriteLine($"[+] Searching for attachments matching: {options.query}");
                        if (options.cloud)
                        {
                            // API endpoint used to search for attachments
                            string attachmentEndpoint = options.url + "/wiki/rest/api/content/search?limit=" + options.limit + "&expand=version&cql=(type=attachment)%20AND%20text%20~%20%22{0}%22";
                            SearchAttachments(options.query, attachmentEndpoint, "cloud");
                        }
                        else
                        {
                            // API endpoint used to search for attachments
                            string attachmentEndpoint = options.url + "/rest/api/content/search?limit=" + options.limit + "&expand=version&cql=(type=attachment)%20AND%20text%20~%20%22{0}%22";
                            SearchAttachments(options.query, attachmentEndpoint, "onprem");
                        }
                    }
                }
                if (!string.IsNullOrEmpty(options.cql))
                {
                    if (Connect(options.url, options.ua, options.user, options.pwd, options.apitoken, options.pat, options.cookies, options.basic, options.form))
                    {
                        // URL-encode CQL parameter to avoid potential Bad Requests
                        string urlEncodedCql = HttpUtility.UrlEncode(options.cql);
                        Console.WriteLine($"[+] Executing CQL query: {options.cql}");
                        if (options.cloud)
                        {
                            // API endpoint used to submit CQL queries
                            string searchEndpoint = options.url + "/wiki/rest/api/content/search?limit=" + options.limit + "&expand=version&cql=" + urlEncodedCql;
                            CqlQuery(searchEndpoint, "cloud");
                        }
                        else
                        {
                            // API endpoint used to submit CQL queries
                            string searchEndpoint = options.url + "/rest/api/content/search?limit=" + options.limit + "&expand=version&cql=" + urlEncodedCql;
                            CqlQuery(searchEndpoint, "onprem");
                        }
                    }
                }

                if (!string.IsNullOrEmpty(options.view))
                {
                    if (Connect(options.url, options.ua, options.user, options.pwd, options.apitoken, options.pat, options.cookies, options.basic, options.form))
                    {
                        Console.WriteLine($"[+] Showing the source code of the page identified by: {options.view}");
                        if (options.cloud)
                        {
                            ViewPage(options.url, options.view, options.pretty, "cloud");
                        }
                        else
                        {
                            ViewPage(options.url, options.view, options.pretty, "onprem");
                        } 
                    }
                }
                if (!string.IsNullOrEmpty(options.download))
                {
                    if (Connect(options.url, options.ua, options.user, options.pwd, options.apitoken, options.pat, options.cookies, options.basic, options.form))
                    {
                        Console.WriteLine($"[+] Downloading the attachment identified by: {options.download}");
                        if (options.cloud)
                        {
                            DownloadAttachment(options.url, options.download, options.b64, options.path, "cloud");
                        }
                        else
                        {
                            DownloadAttachment(options.url, options.download, options.b64, options.path, "onprem");
                        }
                    }
                }
                if (options.spaces)
                {
                    if (Connect(options.url, options.ua, options.user, options.pwd, options.apitoken, options.pat, options.cookies, options.basic, options.form))
                    {
                        Console.WriteLine($"[+] Listing available spaces");
                        if (options.cloud)
                        {
                            // API endpoint used to list spaces
                            string spacesEndpoint = options.url + "/wiki/rest/api/space?limit=" + options.limit;
                            ListSpaces(spacesEndpoint, "cloud");
                        }
                        else
                        {
                            // API endpoint used to list spaces
                            string spacesEndpoint = options.url + "/rest/api/space?limit=" + options.limit;
                            ListSpaces(spacesEndpoint, "onprem");
                        }
                    }
                }
                if (!string.IsNullOrEmpty(options.upload))
                {
                    if (string.IsNullOrEmpty(options.path))
                    {
                        Console.WriteLine("[-] No file path has been provided");
                        return;
                    }
                    if (Connect(options.url, options.ua, options.user, options.pwd, options.apitoken, options.pat, options.cookies, options.basic, options.form))
                    {
                        Console.WriteLine($"[+] Uploading the \"{options.path}\" file as an attachment of the page identified by: {options.upload}");
                        if (options.cloud)
                        {
                            UploadAttachment(options.url, options.upload, options.path, "cloud");
                        }
                        else
                        {
                            UploadAttachment(options.url, options.upload, options.path, "onprem");
                        }
                    }
                }
            }
        }

        public static bool Connect(string confluenceUrl, string userAgent, string username, string password, string apitoken, string pat, string cookies, bool basic, bool form)
        {
            try
            {
                // Set up HTTP client
                ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
                // client.BaseAddress = new Uri(confluenceUrl);

                // Perform initial clean-up of HTTP request headers and cookies. This is needed for certain C2s that load .NET assemblies in-memory without cleaning up
                // If not done, due to the use of HttpClient, subsequent HTTP requests in these C2 frameworks would re-use headers and/or cookies from previous commands
                // This is not required for C2 frameworks that perform appropriate clean-up or run .NET assemblies in temporary AppDomains. However, worth performing initial clean-up to maximise C2 framework support
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
                CookieCollection cookieCollection = cookieContainer.GetCookies(new Uri(confluenceUrl));
                foreach (Cookie previousCookie in cookieCollection)
                {
                    previousCookie.Expired = true; // This is the only way in .NET Framework 4.5 to remove cookies from a CookieContainer
                }

                // Username + Password
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    Console.WriteLine("[+] Authentication method: username + password");
                    Console.WriteLine("[+] Please note that this method is only supported for Confluence Server / Data Center instances");
                    if (basic)
                    {
                        Console.WriteLine("[+] Using Authorization: Basic header");
                        // Confluence Server supports Basic authentication using username+password ("Allow basic authentication on API calls" setting enabled by default)
                        // Convert username:password to base64 and embed it within Authorization: Basic header
                        string encodedCredentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{username}:{password}"));
                        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", encodedCredentials);
                    }
                    else if (form)
                    {
                        string authEndpoint = "/dologin.action";
                        Console.WriteLine($"[+] Sending HTTP POST request with form data to {authEndpoint}");
                        // Building form
                        var formData = new List<KeyValuePair<string, string>>
                        {
                            new KeyValuePair<string, string>("os_username", username),
                            new KeyValuePair<string, string>("os_password", password),
                            new KeyValuePair<string, string>("os_destination", "/index.action"),
                            new KeyValuePair<string, string>("login", "Log in")
                        };
                        var content = new FormUrlEncodedContent(formData);
                        // Send POST request to authenticate
                        HttpResponseMessage response = client.PostAsync(confluenceUrl + authEndpoint, content).Result;
                        // After this, Confluence Server / Data Center will return "Set-Cookie: JSESSIONID=VALUE", which will be automatically submitted by HttpClient on subsequent requests
                    }
                }
                // Username + API token
                else if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(apitoken))
                {
                    Console.WriteLine("[+] Authentication method: username + API token");
                    Console.WriteLine("[+] Please note that this method is only supported for Confluence Cloud instances");
                    // Convert username:apitoken to base64 and embed it within Authorization: Basic header
                    string encodedCredentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{username}:{apitoken}"));
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", encodedCredentials);
                }
                // Personal Access Token (PAT)
                else if (!string.IsNullOrEmpty(pat))
                {
                    Console.WriteLine("[+] Authentication method: Personal Access Token (PAT)");
                    Console.WriteLine("[+] Please note that this method is only supported for Confluence Server / Data Center instances");
                    // Embed PAT within Authorization: Bearer header
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pat);
                }
                // Cookie(s)
                else if (!string.IsNullOrEmpty(cookies))
                {
                    Console.WriteLine("[+] Authentication method: cookie(s)");
                    // Parse the user-entered cookies
                    string[] providedCookies = cookies.Split(';');
                    foreach (string cookie in providedCookies)
                    {
                        string[] cookieParts = cookie.Split('=');
                        if (cookieParts.Length == 2)
                        {
                            // Add the parsed cookie(s) to the cookie container
                            Cookie parsedCookie = new Cookie(cookieParts[0].Trim(), cookieParts[1].Trim());
                            cookieContainer.Add(new Uri(confluenceUrl), parsedCookie);
                            Console.WriteLine($"[+] Using cookie: {cookieParts[0].Trim()}");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[-] Wrong authentication arguments provided");
                    PrintUsage();
                    return false;
                }
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] An error has occurred while attempting to connect to Confluence. Exception: " + e.Message);
                return false;
            }
        }

        public static void CqlQuery(string endpoint, string confluenceType)
        {
            Console.WriteLine($"[+] Search URI: {endpoint}");
            HttpResponseMessage response = client.GetAsync(endpoint).Result;
            if (response.IsSuccessStatusCode)
            {
                string jsonResponse = response.Content.ReadAsStringAsync().Result;
                JObject json = JObject.Parse(jsonResponse); // Parse the JSON string
                JArray resultsArray = (JArray)json["results"]; // Get the results array
                // Iterate through each object in the array
                foreach (JObject result in resultsArray)
                {
                    string title = result["title"]?.ToString();
                    string type = result["type"]?.ToString();
                    string id = result["id"]?.ToString();
                    string versionNumber = result["version"]?["number"]?.ToString();
                    string versionUser = null;
                    if (String.Equals(confluenceType,"cloud"))
                    {
                        versionUser = result["version"]?["by"]?["email"]?.ToString(); // version.by.email only exists in Confluence Cloud
                    }
                    else if (String.Equals(confluenceType, "onprem"))
                    {
                        versionUser = result["version"]?["by"]?["username"]?.ToString(); // version.by.username only exists in Confluence Server / Data Center
                    }
                    string versionName = result["version"]?["by"]?["displayName"]?.ToString();
                    string versionWhen = result["version"]?["when"]?.ToString();
                    Console.WriteLine($"[>] Title: {title} | Type: {type} | ID: {id} | Version #{versionNumber} by {versionName} ({versionUser}) @ {versionWhen}");
                }
            }
            else
            {
                Console.WriteLine($"[-] Failed to run manual CQL query. Error code: {response.StatusCode}");
            }
        }
        public static void SearchPages(string searchQuery, string endpoint, string confluenceType)
        {
            string url = string.Format(endpoint, searchQuery);
            Console.WriteLine($"[+] Search URI (pages): {url}");
            HttpResponseMessage response = client.GetAsync(url).Result;
            if (response.IsSuccessStatusCode)
            {
                string jsonResponse = response.Content.ReadAsStringAsync().Result;
                JObject json = JObject.Parse(jsonResponse); // Parse the JSON string
                JArray resultsArray = (JArray)json["results"]; // Get the results array
                // Iterate through each object in the array
                foreach (JObject result in resultsArray)
                {
                    string title = result["title"]?.ToString();
                    string type = result["type"]?.ToString();
                    string id = result["id"]?.ToString();
                    string versionNumber = result["version"]?["number"]?.ToString();
                    string versionUser = null;
                    if (String.Equals(confluenceType, "cloud"))
                    {
                        versionUser = result["version"]?["by"]?["email"]?.ToString(); // version.by.email only exists in Confluence Cloud
                    }
                    else if (String.Equals(confluenceType, "onprem"))
                    {
                        versionUser = result["version"]?["by"]?["username"]?.ToString(); // version.by.username only exists in Confluence Server / Data Center
                    }
                    string versionName = result["version"]?["by"]?["displayName"]?.ToString();
                    string versionWhen = result["version"]?["when"]?.ToString();
                    Console.WriteLine($"[>] Title: {title} | Type: {type} | ID: {id} | Version #{versionNumber} by {versionName} ({versionUser}) @ {versionWhen}");
                }
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine($"[-] Failed to search pages. Error code: {response.StatusCode}");
            }
        }

        public static void SearchAttachments(string searchQuery, string endpoint, string confluenceType)
        {
            string url = string.Format(endpoint, searchQuery);
            Console.WriteLine($"[+] Search URI (attachments): {url}");
            HttpResponseMessage response = client.GetAsync(url).Result;
            if (response.IsSuccessStatusCode)
            {
                string jsonResponse = response.Content.ReadAsStringAsync().Result;
                JObject json = JObject.Parse(jsonResponse); // Parse the JSON string
                JArray resultsArray = (JArray)json["results"]; // Get the results array
                // Iterate through each object in the array
                foreach (JObject result in resultsArray)
                {
                    string title = result["title"]?.ToString();
                    string id = result["id"]?.ToString();
                    string versionNumber = result["version"]?["number"]?.ToString();
                    string versionUser = null;
                    if (String.Equals(confluenceType, "cloud"))
                    {
                        versionUser = result["version"]?["by"]?["email"]?.ToString(); // version.by.email only exists in Confluence Cloud
                    }
                    else if (String.Equals(confluenceType, "onprem"))
                    {
                        versionUser = result["version"]?["by"]?["username"]?.ToString(); // version.by.username only exists in Confluence Server / Data Center
                    }
                    string versionName = result["version"]?["by"]?["displayName"]?.ToString();
                    string versionWhen = result["version"]?["when"]?.ToString();
                    string fileSize = result["extensions"]?["fileSize"]?.ToString();
                    Console.WriteLine($"[>] Title: {title} | ID: {id} | Size: {fileSize} bytes | Version #{versionNumber} by {versionName} ({versionUser}) @ {versionWhen}");
                }
            }
            else
            {
                Console.WriteLine($"[-] Failed to search attachments. Error code: {response.StatusCode}");
            }
        }

        public static void ViewPage(string confluenceUrl, string id, bool pretty, string confluenceType)
        {
            string pageEndpoint = null;
            if (String.Equals(confluenceType, "cloud"))
            {
                pageEndpoint = confluenceUrl + "/wiki/rest/api/content/" + id + "?expand=body.storage,history.lastUpdated";
            }
            else if (String.Equals(confluenceType, "onprem"))
            {
                pageEndpoint = confluenceUrl + "/rest/api/content/" + id + "?expand=body.storage,history.lastUpdated";
            }
            Console.WriteLine($"[+] Page URI: {pageEndpoint}");
            HttpResponseMessage response = client.GetAsync(pageEndpoint).Result;
            if (response.IsSuccessStatusCode)
            {
                string jsonResponse = response.Content.ReadAsStringAsync().Result;
                JObject json = JObject.Parse(jsonResponse);
                string title = json["title"]?.ToString();
                string sourceCode = json["body"]?["storage"]?["value"]?.ToString();
                string creatorUser = null;
                string lastUpdateUser = null;
                if (String.Equals(confluenceType, "cloud"))
                {
                    creatorUser = json["history"]?["createdBy"]?["email"]?.ToString(); // history.createdBy.email only exists in Confluence Cloud
                    lastUpdateUser = json["history"]?["lastUpdated"]?["by"]?["email"]?.ToString(); // history.lastUpdated.by.email only exists in Confluence Cloud
                }
                else if (String.Equals(confluenceType, "onprem"))
                {
                    creatorUser = json["history"]?["createdBy"]?["username"]?.ToString(); // history.createdBy.username only exists in Confluence Server / Data Center
                    lastUpdateUser = json["history"]?["lastUpdated"]?["by"]?["username"]?.ToString(); // history.lastUpdated.by.username only exists in Confluence Server / Data Center
                }
                string creatorName = json["history"]?["createdBy"]?["displayName"]?.ToString();
                string createdDate = json["history"]?["createdDate"]?.ToString();
                string lastUpdateName = json["history"]?["lastUpdated"]?["by"]?["displayName"]?.ToString();
                string lastUpdateDate = json["history"]?["lastUpdated"]?["when"]?.ToString();
                Console.WriteLine($"[>] Page Title: {title}");
                Console.WriteLine($"[>] Creation Details: {creatorName} ({creatorUser}) @ {createdDate}");
                Console.WriteLine($"[>] Last Update Details: {lastUpdateName} ({lastUpdateUser}) @ {lastUpdateDate}");
                if (pretty)
                {
                    // Dirty HTML parsing so that no external libraries are used
                    string prettifiedSourceCode = Regex.Replace(sourceCode, "<.*?>", ""); // Remove HTML tags
                    prettifiedSourceCode = prettifiedSourceCode.Replace("&nbsp;", " "); // Replace &nbsp; with a space
                    prettifiedSourceCode = prettifiedSourceCode.Replace("&rsquo;", "'"); // Replace &rsquo; with '
                    prettifiedSourceCode = prettifiedSourceCode.Replace("&quot;", "\""); // Replace &quot; with "
                    prettifiedSourceCode = prettifiedSourceCode.Replace("&lt;", "<"); // Replace &lt; with <
                    prettifiedSourceCode = prettifiedSourceCode.Replace("&gt;", ">"); // Replace &gt; with >
                    prettifiedSourceCode = prettifiedSourceCode.Replace("&ndash;", "–"); // Replace &ndash; with –
                    prettifiedSourceCode = prettifiedSourceCode.Replace("&mdash;", "—"); // Replace &mdash; with —
                    prettifiedSourceCode = prettifiedSourceCode.Replace("&amp;", "&"); // Replace &amp; with &
                    Console.WriteLine($"[>] Prettified Source Code:\r\n{prettifiedSourceCode}");
                }
                else
                {
                    Console.WriteLine($"[>] Raw Source Code:\r\n{sourceCode}");
                }
            }
            else
            {
                Console.WriteLine($"[-] Failed to view page. Error code: {response.StatusCode}");
            }
        }

        public static void DownloadAttachment(string confluenceUrl, string id, bool b64, string path, string confluenceType)
        {
            string attachmentEndpoint = null;
            if (String.Equals(confluenceType, "cloud"))
            {
                attachmentEndpoint = confluenceUrl + "/wiki/rest/api/content/" + id;
            }
            else if (String.Equals(confluenceType, "onprem"))
            {
                attachmentEndpoint = confluenceUrl + "/rest/api/content/" + id;
            }
            Console.WriteLine($"[+] Attachment URI: {attachmentEndpoint}");
            HttpResponseMessage response = client.GetAsync(attachmentEndpoint).Result;
            if (response.IsSuccessStatusCode)
            {
                string jsonResponse = response.Content.ReadAsStringAsync().Result;
                JObject json = JObject.Parse(jsonResponse);
                string title = json["title"]?.ToString();
                string versionNumber = json["version"]?["number"]?.ToString();
                string versionUser = null;
                if (String.Equals(confluenceType, "cloud"))
                {
                    versionUser = json["version"]?["by"]?["email"]?.ToString(); // version.by.email only exists in Confluence Cloud
                }
                else if (String.Equals(confluenceType, "onprem"))
                {
                    versionUser = json["version"]?["by"]?["username"]?.ToString(); // version.by.username only exists in Confluence Server / Data Center
                }
                string versionName = json["version"]?["by"]?["displayName"]?.ToString();
                string versionWhen = json["version"]?["when"]?.ToString();
                string fileSize = json["extensions"]?["fileSize"]?.ToString();
                string downloadEndpoint = json["_links"]["download"].ToString(); // If this attribute does not exist, let it fail
                string finalDownloadEndpoint = null;
                if (String.Equals(confluenceType, "cloud"))
                {
                    finalDownloadEndpoint = confluenceUrl + "/wiki" + downloadEndpoint;
                }
                else if (String.Equals(confluenceType, "onprem"))
                {
                    finalDownloadEndpoint = confluenceUrl + downloadEndpoint;
                }
                Console.WriteLine($"[>] Title: {title} | ID: {id} | Size: {fileSize} bytes | Version #{versionNumber} by {versionName} ({versionUser}) @ {versionWhen}");
                Console.WriteLine($"[>] Download URI: {finalDownloadEndpoint}");
                try
                {
                    if (b64)
                    {
                        Console.WriteLine($"[+] Downloading attachment ({title}) as a base64-encoded string");
                        byte[] downloadData = client.GetByteArrayAsync(finalDownloadEndpoint).Result;
                        string b64EncodedAttachment = Convert.ToBase64String(downloadData);
                        Console.WriteLine(b64EncodedAttachment);
                        Console.WriteLine("[+] Download complete");
                    }
                    else
                    {
                        string finalPath = null;
                        if (!string.IsNullOrEmpty(path))
                        {
                            finalPath = path; // Full path specified by user
                        }
                        else
                        {
                            finalPath = title; // Current working directory and the filename of the attachment
                        }
                        Console.WriteLine($"[+] Downloading attachment ({title}) to {finalPath}");
                        HttpResponseMessage downloadResponse = client.GetAsync(finalDownloadEndpoint).Result;
                        downloadResponse.EnsureSuccessStatusCode();
                        using (Stream contentStream = downloadResponse.Content.ReadAsStreamAsync().Result)
                        {
                            using (FileStream fileStream = File.Create(finalPath))
                            {
                                contentStream.CopyTo(fileStream);
                            }
                        }
                        Console.WriteLine("[+] Download complete");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Failed to download attachment. Exception: {e.Message}");
                }
            }
            else
            {
                Console.WriteLine($"[-] Failed to download attachment. Error code: {response.StatusCode}");
            }
        }

        public static void ListSpaces(string spacesEndpoint, string confluenceType)
        {
            Console.WriteLine($"[+] Spaces URI: {spacesEndpoint}");
            HttpResponseMessage response = client.GetAsync(spacesEndpoint).Result;
            if (response.IsSuccessStatusCode)
            {
                string jsonResponse = response.Content.ReadAsStringAsync().Result;
                JObject json = JObject.Parse(jsonResponse); // Parse the JSON string
                JArray resultsArray = (JArray)json["results"]; // Get the results array
                // Iterate through each object in the array
                foreach (JObject result in resultsArray)
                {
                    string id = result["id"]?.ToString();
                    string key = result["key"]?.ToString();
                    string name = result["name"]?.ToString();
                    string type = result["type"]?.ToString();
                    string description = result["_expandable"]?["description"]?.ToString();
                    string link = result["_links"]?["self"]?.ToString();
                    Console.WriteLine($"[>] Key: {key} | Name: {name} | ID: {id} | Type: {type} | Description: {description} | Link: {link}");
                }
            }
            else
            {
                Console.WriteLine($"[-] Failed to view page. Error code: {response.StatusCode}");
            }
        }

        public static void UploadAttachment(string confluenceUrl, string id, string path, string confluenceType)
        {
            string attachmentEndpoint = null;
            if (String.Equals(confluenceType, "cloud"))
            {
                attachmentEndpoint = confluenceUrl + "/wiki/rest/api/content/" + id + "/child/attachment";
            }
            else if (String.Equals(confluenceType, "onprem"))
            {
                attachmentEndpoint = confluenceUrl + "/rest/api/content/" + id + "/child/attachment";
            }
            Console.WriteLine($"[+] Attachment URI: {attachmentEndpoint}");

            // Building form with the file
            using (var formData = new MultipartFormDataContent())
            {
                try
                {
                    // Read the file as a byte array
                    byte[] fileBytes = File.ReadAllBytes(path);
                    // Add the file content to the form data and include it within the "file" parameter
                    var fileContent = new ByteArrayContent(fileBytes);
                    formData.Add(fileContent, "file", Path.GetFileName(path));

                    // "X-Atlassian-Token: nocheck" is needed to prevent "XSRF check failed" errors
                    client.DefaultRequestHeaders.Add("X-Atlassian-Token", "nocheck");
                    // Send POST request to upload attachment
                    HttpResponseMessage response = client.PostAsync(attachmentEndpoint, formData).Result;
                    if (response.IsSuccessStatusCode)
                    {
                        Console.WriteLine("[+] Upload complete");
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to upload attachment. Error code: " + response.StatusCode);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Failed to upload attachment. Exception: {e.Message}");
                }
                finally
                {
                    // Clean up "X-Atlassian-Token" HTTP request header just in case, to ensure compatibility across various C2 frameworks
                    client.DefaultRequestHeaders.Remove("X-Atlassian-Token");
                }
            }
        }
    }
}