#!/usr/bin/env python
#Cyber Patriots Linux Script
#Jack Eakle
#2019
#East Ridge High School




import os
import sys
import subprocess
import fileinput
#from playsound import playsound


#TODO: SSH?, file searching

'''

Write Doc

'''


"""List of all methods

    Methods
    ----------
    updates()
        Updates and Upgrades the system

    firewall()
        Enables ufw firewall

    users()
        Views the /etc/password file for all allowed users in the file /etc/passwd

    root()
        Disables root login in the file sshd_config

    guest()
        Disables guest user in the file /etc/lightdm

    sudo()
        Views users allowed to use the command 'sudo' in the file /etc/sudoers.d

    passwd()
        Changes the password requirements in the file login.defs

    minpassword()
        Changes the minimum requirements for Passwords 

    lockout()
        Sets the lockout policies in common-auth

    checkports()
        Displays the ports on the system

    ipforwarding()
        Disables Ipforwarding
    
    ipspoof()
        Disables ipspoofing

    sharedmemory()
        Disables shared memory in the file fstab.txt

    antivirus()
        Installs the antivirus software ClamTk
    
    php()
        Does something with php and its wacky and i dont really want to use it 

    groups()
        Displayes the groups on the system in the file /etc/group

    media()
        Displays and deletes all media downloaded

    services()
        Displays services that are running

    audit()
        Installs audtid and then opens the autid.conf file 

    rootkit()
        Installs chrootkit 

    softwarecenter()
        Upgrades software center

"""

#find . -iname ____name


#playsound("uhoh.mp3")
user = "test"
"""Allows access to the users home directory"""

x = input("Enter 0 for Auto, Enter 1 for Edits: ")
"""Choosing what section is to be run"""


'''

Auto Running 

'''

def updates():
    """Updates and upgrades the system"""

    os.chdir("/home/" + user)
    subprocess.run(["apt-get", "update"])
    subprocess.run(["apt-get", "upgrade"])


def firewall():
    """Enables UFW firewall"""

    os.chdir("/home/" + user)
    subprocess.run(["ufw", "enable"])

def users():
    """Displays all users on the system"""

    os.chdir("/home/" + user)
    subprocess.run(["nano", "/etc/passwd"])

def root():
    """Disables root login

        Changes 'PermitRootLogin' to 'PermitRootLogin no'
    """

    os.chdir("/home/" + user)
    os.chdir('/etc/ssh')
    subprocess.run(['sed', '-i', '/PermitRootLogin/c\PermitRootLogin no', 'sshd_config'])
    

def guest():
    """Disables guest account

    Automatically changes 'allow-guest' to allow-guest=false
    """

    os.chdir("/home/" + user)
    subprocess.run(["cd", "/etc/lightdm"])
    os.chdir('/etc/lightdm')
    file = open('lightdm.conf', 'r+w')
    file.write("allow-guest=false")
    file.close()


def sudo():
    """Displays all users that have access to the 'sudo' command"""

    os.chdir("/home/" + user)
    subprocess.run(["nano", "/etc/sudoers.d"])

def password():
    """Changes password requirements

    Automatically edits the login.defs file:

        PASS_MIN_DAYS -> PASS_MIN_DAYS 7

        PASS_MAX_DAYS -> PASS_MAX_DAYS 90

        PASS_WARN_AGE -> PASS_WARN_AGE 14
    """
    os.chdir("/home/" + user)
    os.chdir('/etc')
    subprocess.run(['sed', '-i', '/PASS_MIN_DAYS/c\PASS_MIN_DAYS  7', "login.defs"])
    subprocess.run(['sed', '-i', '/PASS_MAX_DAYS/c\PASS_MAX_DAYS  90', "login.defs"])
    subprocess.run(['sed', '-i', '/PASS_WARN_AGE/c\PASS_WARN_AGE  14', "login.defs"])
   

def minpassword():
    """Changes the minimum length and password memory

    Automatically edits the common-password file:

        /pam_unix.so -> pam unix.so minlen=8 remember=5

        /pam.cracklib.so -> pam.crack.lib.so ucredit =-1 lcredit =-1 dcredit =-1 ocredit =-1
    """
    os.chdir("/home/" + user)
    os.chdir('/etc/pam.d')
    subprocess.run(['sed', '-i', '/pam_unix.so]/c\pam unix.so minlen=8 remember=5', 'common-password'])
    subprocess.run(['sed', '-i', '/pam.cracklib.so/c\pam.crack.lib.so ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1', 'common-password'])


def lockout():
    """Edits the lockout policy on password attempts

    Automatically changes the common-auth file:

        pam_tally.so -> pam_tally.so deny=5 unlock_time=1800
    """
    os.chdir("/home/" + user)
    os.chdir('/etc/pam.d')
    subprocess.run(['sed', '-i', '/pam_tally.so/c\pam_tally.so deny=5 unlock_time=1800', 'common-auth'])


def checkPorts():
    """Displays ports on the system"""
    os.chdir("/home/" + user)
    subprocess.run(["ss", "-ln"])


def ipforwarding():
    """Disables Ip Forwarding"""
    os.chdir("/home/" + user)
    subprocess.run(["echo", "0", "|", "sudo", "tee", "/proc/sys/net/ipv4/ip_forward"])


def ipspoof():
    """Turns off IP-Spoofing on the system"""
    os.chdir("/home/" + user)
    subprocess.run(["echo", "'nospoofon'", "|", "sudo tee -a /etc/host.conf"])


def sharedMemory():
    os.chdir("/home/" + user)
    os.chdir("/etc")
    #TODO: break up string
    subprocess.run(['sed', '-i', '/tmpfs/c\tmpfs /run/shm', 'fstab.txt'])


def antivirus():
    os.chdir("/home/" + user)
    subprocess.run(["apt-get", "install", "clamTK"])


#UH OH    STIIIIIINKYYYYYY   PPPOOOOOOOOOO AHAHAHAHAHHAH
def php():
    os.chdir("/home/" + user)
    subprocess.run(["nano", "/etc/php5/apache2/php.ini"])

    """
    disable_functions = exec,system,shell_exec,passthru
    register_globals = Off
    expose_php = Off
    display_errors = Off
    track_errors = Off
    html_errors = Off
    magic_quotes_gpc = Off
    mail.add_x_header = Off
    session.name = NEWSESSID
    """


def groups():
    os.chdir("/home/" + user)
    subprocess.run(["nano", "/etc/group"])


def media():
    #TODO: could delete all media in here 
    os.chdir("/home/" + user)
    subprocess.run(["cd", "/home"])
    subprocess.run(["ls", "-Ra", "*"])
    subprocess.run(["rm", "-rfv", ""])


def services():
    os.chdir("/home/" + user)
    subprocess.run(["service", "--status-all"])


def audit():
    os.chdir("/home/" + user)
    subprocess.run(["apt-get", "install", "auditd"])
    subprocess.run(["auditctl", "-e", "1"])
    subprocess.run(["nano", "/etc/audit/atuditd.conf"])


def rootKit():
    os.chdir("/home/" + user)
    subprocess.run(["apt-get", "install", "chkrootkit"])


def appstore():
    os.chdir("/home/" + user)
    subprocess.run(["apt-get",  "upgrade",  "software-center"])

def userpasswd():
    os.chdir("/home/" + user)
    subprocess.run(["chpasswd"])


##SPOOKY SPOOKY DO NOT RUN UNLESS TOLD TO OR LAST DITCH MOVE 
def ipv6():
    os.chdir("/home/" + user)
    subprocess.run(['echo', '"nospoof', 'on"', '|', 'sudo', 'tee', '-a', '/etc/host.conf'])


def kernelcheck():
    os.chdir("/home/" + user)
    subprocess.run(['uname', '-sr'])

def kernelupdate():
    os.chdir("/home/" + user)
    subprocess.run(['add-apt-repository', 'ppa:teejee2008/ppa'])
    subprocess.run(['apt-get', 'install', 'ukuu'])


def remoteDesktop():
    os.chdir("/home/" + user)
    subprocess.run(["lsof", "-i :" + "3389"])


def killSSH():
    os.chdir("/home/" + user)
    subprocess.run(["lsof", "-i :" + '22'])


def killtelnet():
    os.chdir("/home/" + user)
    subprocess.run(["lsof", "-i :" + '23'])


def cookie():
    os.chdir("/home/" + user)
    subprocess.run(['sysctl', '-n', 'net.ipv4.tcp_syncookies'])



'''

Editable 

'''
def checkDirectory(user):
    os.chdir("/home/" + user)
    os.chdir(' /home')
    subprocess.run(["sudo", "ls"< "-Ra", user])

def filePermission(user, permission, access, filepath):
    os.chdir("/home/" + user)
    subprocess.run(["chmod", user, permission, access, filepath])

def addGroup(name):
    os.chdir("/home/" + user)
    subprocess.run(["addgroup", "[", "name", "]"])

def closePort(port):
    os.chdir("/home/" + user)
    subprocess.run(["lsof", "-i :" + port])

def printByMod(name, time):
    os.chdir("/home/" + user)
    subprocess.run(["find", "/", "-name", "name", "-mtime", time])

def removeApp(appName):
    os.chdir("/home/" + user)
    subprocess.run(["apt-get", "--purge remove", appName])


def searchByFileType(fileLocation,fileType):
    os.chdir("/home/" + user)
    subprocess.run(["find ", + fileLocation, "-name " + "*." + fileType])

#make sure to put contents in quotes ig?
def searchByFileContents(fileLocation, contents):
    os.chdir("/home/" + user)
    subprocess.run(["find" + fileLocation + "-type f -exec grep" + contents + "'{}' \; -print"])


def deleteFile(name):
    os.chdir("/home/" + user)
    subprocess.run(["find", ".", "-name", name ,"-delete"])


def removeUser(user):
    os.chdir("/home/" + user)
    subprocess.run(["userdel", "-r", user])

def userID(id):
    os.chdir("/home" + user)
    subprocess.run(["id", "-u", id])


'''

Switch Case statement 

'''

def switch_auto(func):
    
    if func == "0" or "update" or "updates" or "apt-get update":
        updates()
        return func
    elif func == "1" or "firewall" or "enable firewall" or "apt-get firewall":
        firewall()
        return func
    elif func == "2" or "user" or "users" or "view users":
        users()
        return func
    elif func == "3" or "root" or "sshd_config" or "disable root" or "disable root login":
        root()
        return func
    elif func == "4" or "guest" or "lightdm.conf" or "disable guest" or "disable guest login":
        guest()
        return func
    elif func == "5" or "sudo" or "sudoers.d" or "view sudo":
        sudo()
        return func
    elif func == "6" or "password" or "login.defs" or "password rules":
        password()
        return func
    elif func == "7" or "minpassword" or "common-password" or "minimum password":
        minpassword()
        return func
    elif func == "8" or "lockout" or "pam_tally.so":
        lockout()
        return func
    elif func == "9" or "check ports":
        checkPorts()
        return func
    elif func == "10" or "ipforwarding":
        ipforwarding()
        return func
    elif func == "11" or "ipspoof":
        ipspoof()
        return func
    elif func == "12" or "shared memory":
        sharedMemory()
        return func
    elif func == "13" or "install antivirus":
        antivirus()
        return func
    elif func == "14":
        php()
        return func
    elif func == "15" or "groups" or "show groups":
        groups()
        return func
    elif func == "16" or "delete media" or "remove media":
        media()
        return func
    elif func == "17" or "view services":
        services()
        return func
    elif func == "18":
        audit()
        return func
    elif func == "19":
        rootKit()
        return func
    elif func == "20":
        appstore()
        return func
    elif func == "21":
        userpasswd()
        return func
    elif func == "22":
        ipv6()
        return func
    elif func == "23":
        kernelcheck()
        return func
    elif func == "24":
        kernelupdate()
        return func
    elif func == "25":
        remoteDesktop()
        return func
    elif func == "26":
        killSSH()
        return func
    elif func == "27":
        killtelnet()
        return func
    elif func == "28":
        cookie()
        return func
    elif func == "29":
        x+1
        return x


def switch_edit(edit, mod):
    if edit == "0":
        checkDirectory(mod)
        return edit
    elif edit == "1":
        filePermission(mod)
        return edit
    elif edit == "2":
        addGroup(mod)
        return edit
    elif edit == "3":
        closePort(mod)
        return edit
    elif edit == "4":
        printByMod(mod)
        return edit
    elif edit == "5":
        removeApp(mod)
        return edit
    elif edit == "6":
        searchByFileContents(mod)
        return edit
    elif edit == "7":
        searchByFileType(mod)
        return edit
    elif edit == "8":
        deleteFile(mod)
        return edit
    elif edit == "9":
        removeUser(mod)
    elif edit == "10":
        userID(mod)
        return edit
    elif edit == "11":
        x-1
        return x 
    
if __name__ == "__main__":
    #These are the auto running methods
    if x == "0":
        while(x == "0"):
            func = input("Enter what method you want to run: ")
            switch_auto(func)
    #edit-able ones go here
    if x == "1":
        while x == "1":
            edit = input("Enter what method you want to run: ")
            mod = input("Enter args: ")
            #dont work
            switch_edit(edit, mod)
