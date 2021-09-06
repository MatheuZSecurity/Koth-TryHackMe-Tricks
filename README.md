# Koth TryHackMe - Tricks

## Examples

## looking for root permissions

* you can use find to search for permissions with root

```
find / -type f \( -perm -4000 -o -perm -2000 \) -print
```


## using chattr

* you can use this to make the file immutable and therefore keep your name in this file.

```
chattr -i /root/king.txt
```

## fixing the vulnerability in /etc/sudoers, for example

```
# User privilege specification
root ALL=(ALL=ALL) ALL
teste ALL=(root) SETENV:NOPASSWD: /usr/bin/git *, /usr/bin/chattr
test1 ALL=(root) NOPASSWD: /bin/su test1, /usr/bin/chattr
```

* here you can see that user teste and teste1 has root permission on the git and su binary, to fix this just remove everything from the teste and teste1 there

```
root ALL=(ALL=ALL) ALL
```

* and it will be like that, so there will be no way to climb privilege by su and git

## using find

* you can use find to look for flags

```
find / -name flag.txt 2>/dev/null
find / -name user.txt 2>/dev/null
find / -name .flag 2>/dev/null
find / -name flag 2>/dev/null
find / -name root.txt 2>/dev/null
```
## full tty shell

* tweaking your shell, if you get a reverse shell and you ctrl + c and your shell closes/stops, this will help you and you can edit, give ctrl + c at will

```
python3 -c 'import pty; pty.spawn("/bin/sh")'
export TERM=xterm
Ctrl + z
stty raw -echo;fg
```

## Changing the SSH port (AGAINST RULES/NOT RECOMMENDED)

* to change the ssh port, we will use the following command

```
nano /etc/ssh/sshd_config
```
* now we notice that SSH by default port is on port 22

```
Include /etc/ssh/sshd_config.d/*.conf

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key
```

* IF YOU DO THIS, DO IT IN PRIVATE ROOMS WITH YOUR FRIENDS FOR FUN, BECAUSE IN THE PUBLIC ROOM YOU WILL BE PUNISHED !!

* but we can change port 22 from SSH to a high port

```
Include /etc/ssh/sshd_config.d/*.conf

Port 55999
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key
```

* now just restart the ssh service to change which port you chose

```
service sshd restart
 ```
## breaking into the shell of users logged into SSH (NOT RECOMMENDED,DO THIS ONLY IN PRIVATE ROOMS WITH YOUR FRIENDS FOR FUN)

* you can use the following command to break into the shell of other logged in users

```
script -f /dev/pts/1
```

* for you to know which pts (pseudo slave terminal) the user is connected, just use the following command in the terminal: w , then just see which pts the user is and use the command

## how to see who is logged into the system

* you can use the following commands to see who is logged into ssh/system

```
w
who
ps aux | grep pts
```

## killing session of a user logged into ssh/system

* to kill someone's session just use the following command

```
pkill -9 -t pts/1
```

* as explained in some examples above, just put the pts of the user you want to remove from the machine

## changing ssh user password

* to change a user's password just use the following command

```
passwd [UserName]
```

* you can change ssh keys

## defending box

* Look for common ways to fix a box, for example: changing ssh keys, changing passwords, look for running processes or even in cronjobs

* Always set your persistence so that even if someone kicks you out, you have multiple ways to get back.

* So start fixing things in the box. Fix security issues, not legitimate services. For example, disabling ssh is NOT allowed unless it is an intentionally broken ssh installation.


## Some useful links

[for privilege escalation](https://gtfobins.github.io/).

[this will help you with reverse shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

[this will help you with ciphers, hashes, etc.](https://gchq.github.io/CyberChef/)

## Note 

Don't do anything wrong on the koth machines, please respect all the rules for everyone to have a great experience and a great game

https://docs.tryhackme.com/docs/koth/king-of-the-hill

## more content here soon!
