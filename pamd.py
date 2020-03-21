from API import Module
from commands import *
from tree import 

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
        self.tree.selected_dirs = ['/lib/security']
    
    def checkPamdProfiles(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка важных профилей PAM'), 'title')
        self.result.update()
        self.vulnerable = False
        result = command_seq('ls  -1 /etc/pamd')[0].split('\n')
        self.result.insert('end', '{}\n'.format('Профили PAM, присутствующие в системе'))
        
        for prof in result:
            self.result.insert('end', 'Профиль:{}\n'.format(prof))

        for prof in self.profiles:
            if prof in result:
                continue
            else:
                self.result.insert('end', 'Профиль:{} отсутствует в системе\n'.format(prof))
                self.vulnerable = True
            if self.vulnerable:
                self.result.insert('end', '{}\n'.format('Внимание! Некоторые важные модули отсутсвуют в системе.\n'))
                self.result.insert('end', "Рекомендация:\n"
		        + "Проверьте необходимость модулей выше и при необходимости добавьте добавьте соответствующие профили в папку /etc/pamd\n\n") 
            else:
                self.result.insert('end', '{}\n'.format("Профили для всех важных системных модулей присутстыую!\n"))
        return

    def checkVulnerableParameters(self):
        self.result.insert('end', '\n{}\n\n'.format('Поиск профилей PAM с уязвимыми параметрами'), 'title')
        self.result.update()
        self.vulnerable = False

        result = command_seq('ls  -1 /etc/pamd')[0].split('\n')
        
        for prof in result:
            profile = command_seq('cat < %' % prof)[0]
            if 'sufficient' in profile:
                self.vulnerable = True
                self.result("end", 'Профиль {} имеет опцию sufficient\n',format(prof))
            if 'optional' in profile:
                self.vulnerable = True
                self.result("end", 'Профиль {} имеет опцию optional\n',format(prof))
            
        if self.vulnerable:
            self.result.insert('end', '{}\n'.format('Эти профили PAM содкржат потенцальную уязвимость .\n'))
            self.result.insert('end', "Рекомендация:\n"
	        + "Проанализируйте эти объекты PAM и перепишите их содержимое, если обнаружите, что они действительно образуют уязвимость в безопасности.\n\n") 
        else:
            self.result.insert('end', '{}\n'.format("Все профили PAM безопасны!\n"))
        return

    def checkPamFiles(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка режима доступа файлов PAM'), 'title')
        self.result.update()
        self.vulnerable = False

        result = self.tree.file_permissions()
        #result = command_seq('ls  -l /lib/security')[0].split('\n')
        for filepers in result:
            if filepers[3] != 'root' and filepers[2] != 'root':
                self.vulnerable = True
                self.result("end", 'У файла {} владелец или группа владельца не root\n',format(filepers[8]))
            
        if self.vulnerable:
            self.result.insert('end', '{}\n'.format('Вышеуказанные файлы модуля PAM содержат потенциальную уязвимость.\n'))
            self.result.insert('end', "Рекомендация:\n"
	        + "Проанализируйте эти объекты PAM и если необходимо исправьте нарушения.\n\n") 
        else:
            self.result.insert('end', '{}\n'.format("Все файлы модуля PAM безопасны!\n"))
        return
