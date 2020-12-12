#!/usr/bin/env python
#Cyber Patriots Linux Script
#Jack Eakle
#2020
#East Ridge High School

import os
import os.path
from os import path
import sys
import subprocess
import fileinput
import time
import inspect
from itertools import ifilter 
import logging



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



user = "jack"
logging.basicConfig(filename="scriptLog.log", level=logging.INFO)
"""Allows access to the users home directory"""

def search(fileName, string):
    with open(fileName) as f:
        if 'string' in f.read():
            return True

def write(doc, text):
    file = open(doc, 'a')
    file.write("\n")
    file.write(text)
    file.close()
    logging.warn("Had to write to file")
    
class Auto(object):

    def aaupdates(self):
        """Updates and upgrades the system"""

        os.chdir("/home/" + user)
        subprocess.call(["apt", "update"])
        subprocess.call(["apt", "upgrade"])


    def firewall(self):
        """Enables UFW firewall"""

        os.chdir("/home/" + user)
        subprocess.call(["ufw", "enable"])
        subprocess.call(["ufw", "allow", "8080"])
        subprocess.call(["ufw", "deny", "22"])
        subprocess.call(["ufw", "deny", "23"])
        subprocess.call(["ufw", "deny", "3389"])
        logging.info("firewall enabled")


    def ssh(self):
        """Disables root login
            Changes 'PermitRootLogin' to 'PermitRootLogin no'
        """

        os.chdir("/home/" + user)
        os.chdir('/etc/ssh')
        if path.isfile('sshd_config') is True: 
            if search("sshd_config", "PermitRootLogin") is True:
                subprocess.call(['sed', '-i', '/^#/!s/PermitRootLogin/PermitRootLogin no', 'sshd_config'])
            else:
                write("sshd_config", "PermitRootLogin no") 
                logging.error('Could not find PermitRootLogin')

            if search("sshd_config", "#Port 22") is True:
                subprocess.call(["sed", "-i", "/#Port 22/c\Port 1024"])
            else:
                write("sshd_config", "Port 1024")
                logging.error('Could not find port')

        elif path.isfile("ssh_config") is True:
            if search("ssh_config", "PermitRootLogin") is True:
                subprocess.call(['sed', '-i', '/^#/!s/PermitRootLogin/PermitRootLogin no', 'ssh_config'])
            else:
                write("sshd_config", "PermitRootLogin no") 
                logging.error('Could not find PermitRootLogin')
            
            if search("ssh_config", "#Port 22") is True:
                subprocess.call(['sed', '-i', '/#Port 22/c\Port 1024', 'ssh_config'])
            else:
                write("sshd_config", "Port 1024") 
                logging.error('Could not find PermitRootLogin')
        else:
            subprocess.call(['touch', 'sshd_config'])
            write("sshd_config", "PermitRootLogin no")
            logging.info("Had to create the file sshd_config")


    def zzguest(self):
        """Disables guest account
        Automatically changes 'allow-guest' to allow-guest=false
        """

        os.chdir("/home/" + user)
        os.chdir('/etc/lightdm')
        if path.isfile('lightdm.conf') is True:
            write("lightdm.conf", "allow-guest=false")
        else:
            subprocess.call(['touch', 'lightdm.conf'])
            write("lightdm.conf", "allow-guest=false")
            logging.info('Had to create file lightdm.conf')
        
        subprocess.call(["restart", "lightdm"])


    def password(self):
        #TODO: Not replacing, needs debugging
        """Changes password requirements
        Automatically edits the login.defs file:
            PASS_MIN_DAYS -> PASS_MIN_DAYS 7
            PASS_MAX_DAYS -> PASS_MAX_DAYS 90
            PASS_WARN_AGE -> PASS_WARN_AGE 14
        """

        os.chdir("/home/" + user)
        os.chdir('/etc')
        if path.isfile("login.defs") is True:
            if search("login.defs", "PASS_MIN_DAYS") is True:
                subprocess.call(['sed', '-i', '/^#/!s/.*PASS_MIN_DAYS/PASS_MIN_DAYS 7/', "login.defs"])
            else:
                write("login.defs", "PASS_MIN_DAYS 7")

            if search("login.defs", "PASS_MAX_DAYS") is True:
                subprocess.call(['sed', '-i', '/^#/!s/.*PASS_MAX_DAYS/PASS_MAX_DAYS 90/', "login.defs"])
            else: 
                write("login.defs", "PASS_MAX_DAYS 90")

            if search("login.defs", "PASS_WARN_AGE") is True:
                subprocess.call(['sed', '-i', '/^#/!s/.*PASS_WARN_AGE/PASS_WARN_AGE 14/', "login.defs"])
            else:
                write("login.defs", "PASS_WARN_AGE 14")

        else:
            subprocess.call(['touch', 'login.defs'])
            write("login.defs", "PASS_MIN_DAYS 7")
            write("login.defs", "PASS_MAX_DAYS 90")
            write("login.defs", "PASS_WARN_AGE 14")
            logging.info("Had to create the file login.defs")

    

    def minpassword(self):
        """Changes the minimum length and password memory
        Automatically edits the common-password file:
            /pam_unix.so -> pam unix.so minlen=8 remember=5
            /pam.cracklib.so -> pam.crack.lib.so ucredit =-1 lcredit =-1 dcredit =-1 ocredit =-1
        """

        os.chdir("/home/" + user)
        os.chdir('/etc/pam.d')

        if path.isfile("common-password") is True: 
            if search("common-password", "pam_unix.so") is True:
                subprocess.call(['sed', '-i', '/^#/!s/pam_unix.so/pam_unix.so minlen=8 remember=5', 'common-password'])
            else:
                write("common-password", "pam_unix.so minlen=8 remember=5")
            
            if search("common-password", "pam.cracklib.so") is True:
                subprocess.call(['sed', '-i', '/^#/!s/pam.cracklib.so/pam.crack.lib.so ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1', 'common-password'])
            else:
                subprocess.call(["apt-get", "install", "libpam-cracklib"])
                write("common-password", "pam.crack.lib.so ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1")
        else:
            subprocess.call('touch', 'common-password')
            subprocess.call(["apt-get", "install", "libpam-cracklib"])
            write("common-password", "pam_unix.so minlen=8 remember=5")
            write("common-password", "pam.crack.lib.so ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1")
            logging.info("Had to create file common-password")
            

    def lockout(self):
        """Edits the lockout policy on password attempts
        Automatically changes the common-auth file:
            pam_tally.so -> pam_tally.so deny=5 unlock_time=1800
        """
        os.chdir("/home/" + user)
        os.chdir('/etc/pam.d')

        if path.isfile("common-auth") is True:
            if search("common-auth", "pam_tally.so") is True:
                subprocess.call(['sed', '-i', '/^#/!s/pam_tally.so/pam_tally.so deny=5 unlock_time=1800', 'common-auth'])
            else:
                write("common-auth", "pam_tally.so deny=5 unlock_time=1800")
        else:
            subprocess.call('touch', 'common-auth')
            write("common-auth", "pam_tally.so deny=5 unlock_time=1800")
            logging.info("Had to create file common-auth")


    def ipforwarding(self):
        """Disables Ip Forwarding"""
        os.chdir("/home/" + user)
        subprocess.call(["echo", "0", "|", "sudo", "tee", "/proc/sys/net/ipv4/ip_forward"])


    def ipspoof(self):
        """Turns off IP-Spoofing on the system"""
        os.chdir("/home/" + user)
        subprocess.call(["echo", "'nospoofon'", "|", "sudo tee -a /etc/host.conf"])


    def sharedMemory(self):
        #TODO: Haivng some kind of TypeError on line 36-38 r
        os.chdir("/home/" + user)
        os.chdir("/etc")

        if path.isfile("fstab.txt") is True: 
            if search("fstab.txt", "tmpfs") is True:
                subprocess.call(['sed', '-i', '/^#/!s/tmpfs/tmpfs /call/shm', 'fstab.txt'])
            else:
                write("fstab.txt", "tmpfs /call/shm")
        else:
            subprocess.call("touch", "fstab.txt")
            write("fstab.txt", "tmpfs /call/shm")
            logging.info("Had to create file Fstab.txt")


    def antivirus(self):
        os.chdir("/home/" + user)
        subprocess.call(["apt-get", "install", "clamTK"])


    #UH OH    STIIIIIINKYYYYYY   PPPOOOOOOOOOO AHAHAHAHAHHAH
    '''
    def php():
        os.chdir("/home/" + user)
        subprocess.call(["nano", "/etc/php5/apache2/php.ini"])

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
    '''

    


    def appstore(self):
        os.chdir("/home/" + user)
        subprocess.call(["apt-get",  "upgrade",  "software-center"])

    ##SPOOKY SPOOKY DO NOT call UNLESS TOLD TO OR LAST DITCH MOVE
    '''
    def ipv6():
        os.chdir("/home/" + user)
        subprocess.call(['echo', '"nospoof', 'on"', '|', 'sudo', 'tee', '-a', '/etc/host.conf'])
    '''

    '''
    #Unsure about dis
    def kernelupdate(self):
        os.chdir("/home/" + user)
        subprocess.call(['add-apt-repository', 'ppa:teejee2008/ppa'])
        subprocess.call(['apt-get', 'install', 'ukuu'])
    '''

    def cookie(self):
        os.chdir("/home/" + user)
        subprocess.call(['sysctl', '-n', 'net.ipv4.tcp_syncookies'])

    #TODO: Unknown code
    
    def groupAddition(self):
        os.chdir("/home/" + user)
        subprocess.call(['cut', '-d', '-f', '1', '/etc/passwd'])
    

    def privateDirectory(self):
        os.chdir("/home/" + user)
        subprocess.call(["chmod", "700", "/home/" + user])
    

    def encrypt(self):
        os.chdir("/home/" + user)
        subprocess.call(["apt-get", "install", "ecryptfs-utils", "cryptsetup"])
        subprocess.call(["ecryptfs-migrate-home", "-u", user])
    
    def zzaudit(self):
        #TODO: Conflicts with other audit, idk
        os.chdir("/home/" + user)
        subprocess.call(["apt-get", "install", "auditd"])
        subprocess.call(["auditctl", "-e", "1"])
        subprocess.call(["nano", "/etc/audit/atuditd.conf"])
    

    def rootDisable(self):
        os.chdir("/home/" + user)
        subprocess.call(["passwd", "-l", "root"])

            

class Printable(object):

    def services(self):
        os.chdir("/home/" + user)
        subprocess.call(["service", "--status-all"])

    def kernelcheck(self):
        os.chdir("/home/" + user)
        subprocess.call(['uname', '-sr'])

    def groups(self):
        os.chdir("/home/" + user)
        subprocess.call(["cat", "/etc/group"])

    def checkPorts(self):
        """Displays ports on the system"""
        os.chdir("/home/" + user)
        subprocess.call(["ss", "-ln"])

    def sudo(self):
        """Displays all users that have access to the 'sudo' command"""

        os.chdir("/home/" + user)
        subprocess.call(["cat", "/etc/sudoers.d"])

    def users(self):
        """Displays all users on the system"""

        os.chdir("/home/" + user)
        subprocess.call(["cat", "/etc/passwd"])


    def noUserFiles(self):
        os.chdir("/home/" + user)
        subprocess.call(["find", "/", "-nogroup", "-nouser"])
    
    def rootKit(self):
        os.chdir("/home/" + user)
        subprocess.call(["apt-get", "install", "chkrootkit"])
        subprocess.call(["chrootkit"])
    
    def media(self):
        #TODO: could delete all media in here 
        os.chdir("/home/" + user)
        subprocess.call(["cd", "/home"])
        subprocess.call(["ls", "-Ra", "*"])



class Input(object):
    def checkDirectory(self):
        os.chdir("/home/" + user)
        os.chdir(' /home')
        user = input("Enter the username you want to check: ")
        subprocess.call(["sudo", "ls"< "-Ra", user])

    def filePermission(self, user, permission, access, filepath):
        os.chdir("/home/" + user)
        subprocess.call(["chmod", user, permission, access, filepath])

    def addGroup(self, name):
        os.chdir("/home/" + user)
        subprocess.call(["addgroup", "[", name, "]"])

    def closePort(self, port):
        os.chdir("/home/" + user)
        subprocess.call(["lsof", "-i :" + port])

    def printByMod(self, name, time):
        os.chdir("/home/" + user)
        subprocess.call(["find", "/", "-name", "name", "-mtime", time])

    def removeApp(self, appName):
        os.chdir("/home/" + user)
        subprocess.call(["apt-get", "--purge remove", appName])


    def searchByFileType(self, fileLocation,fileType):
        os.chdir("/home/" + user)
        subprocess.call(["find ", + fileLocation, "-name " + "*." + fileType])

    #make sure to put contents in quotes ig?
    def searchByFileContents(self, fileLocation, contents):
        os.chdir("/home/" + user)
        subprocess.call(["find" + fileLocation + "-type f -exec grep" + contents + "'{}' \; -print"])


    def deleteFile(self, name):
        os.chdir("/home/" + user)
        subprocess.call(["find", ".", "-name", name ,"-delete"])


    def removeUser(self, user):
        os.chdir("/home/" + user)
        subprocess.call(["userdel", "-r", user])

    def userID(self, id):
        os.chdir("/home" + user)
        subprocess.call(["id", "-u", id])

    def userpasswd(self, user, password):
        os.chdir("/home/" + user)
        subprocess.call(["chpasswd"])
    
    def passwdCheck(self, user):
        os.chdir("/home/" + user)
        subprocess.call(["passwd", "--status", user])

    def switch(arg):
        switcher = {
            0: checkDirectory,
            1: filePermission,
            2: addGroup,
            3: closePort,
            4: printByMod,
            5: removeApp,
            6: searchByFileType,
            7: searchByFileContents,
            8: deleteFile, 
            9: removeUser,
            10: userID,
            11: userpasswd,
            12: passwdCheck
        }


if __name__ == "__main__":
    tester = Auto()
    attrs = (getattr(tester, name) for name in dir(tester))
    methods = ifilter(inspect.ismethod, attrs)
    for method in methods:
        try: 
            method()
        except TypeError:
            pass
    
    #TODO: Seet root passowrd to more complex one
    '''
    print("Welcome to Jacks python script")
    print(" ")
    print("Automatic points [1]")
    print(" ")
    print("Printable points [2]")
    print(" ")
    print("Choose what actions to run [3]")
    int value = input("Enter 1,2,3: ")

    if (value = 1):
        tester = Auto()
        attrs = (getattr(tester, name) for name in dir(tester))
        methods = ifilter(inspect.ismethod, attrs)
        for method in methods:
            try:
                method()
            except TypeError:
                pass
    elif (value = 2):
        tester = Printable()
        attrs = (getattr(tester, name) for name in dir(tester))
        methods = ifilter(inspect.ismethod, attrs)
        for method in methods:
            try:
                method()
            except TypeError:
                pass
    elif(value =3):
        while(loop = 0):
            int choice = input("Enter the dictionary number of what method you want to run. Look in the readme to see numbers: ")
            edit.switch(choice)
            loop = input("Enter 1 to exit loop, Enter 0 to repeat: ")
    '''
   