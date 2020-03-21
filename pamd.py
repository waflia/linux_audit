from API import Module
from commands import *

class PAM_Tab(Module):

    def __init__(self, master):
        super().__init__(master, False)

        self.profiles = ["common-account-pc", "common-auth-pc", "common-password-pc",
                         "common-session-pc", "chage", "chfn", "crond", "gdm-autologin",
                         "getty", "gnome-screensaver", "gnomesu-pam", "init", "login",
                         "login.old", "other", "passwd", "remote", "rlogin", 
                         "shadow", "smtp", "sshd", "su", "sudo", "syslog", "useradd" ]
                         
        self.functions = {
            "Анализ контроля PAM": self.checkPamdProfiles,
            "Поиск профилей с уязвимыми параметрами": self.checkVulnerableParameters,
            "Безопасность файлов модуля PAM":self.checkPamFiles,
        }
        self.setFuncs(self.functions)
        self.setParams(header = "модуля PAM")
    
    def checkPamdProfiles(self):
        pass

    def checkVulnerableParameters(self):
        pass
s
    def checkPamFiles(self):
        pass