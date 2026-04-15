#Hack The Box "TwoMillion" Writeup
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
but the second one ( makeInviteCode() )

