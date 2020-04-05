from API import Module
from commands import command_seq

class Procs_Tab(Module):
    def __init__(self, master):
        super().__init__(master, False)

        self.functions = {
            "Процессы запущенные\n от имени root": self.checkRootProcs,
            "Процессы с различными\nUID и EUID ": self.checkUIDProcs,
            "Процессы с различными\n GID и EGID ":self.checkGIDProcs,
            #"Процессы ограниченные\nchroot":self.checkChrootProcs,
            "Объекты atd": self.checkATD,
            "Объекты crontab": self.checkCrontab,
            "Анализ файлов crontab": self.checkCrontabFiles,
        }
        self.setFuncs(self.functions)
        self.setParams(header = "процессов в системе")
    
    def checkRootProcs(self):
        self.result.insert('end', '\n{}\n\n'.format('Анализ процессов, запущенных от имени root'), 'title')
        self.result.update()

        procs = command_seq("sudo ps -u root -U root u | awk '{print $2,$7,$8,$9,$10,$11}'", self.password)[0].split('\n')
        if procs != '':
            self.result.insert('end', "Процессы, запущенные от имени root:\n")
            for proc in procs:
                self.result.insert('end', '{}\n'.format(proc))
            self.result.insert('end', "Рекомендация:\n"
                + "Проанализируйте данные процессы на предмет подозрительной активности и,"
                + "если необходимо, завершите их командой pkill <Имя процесса>\n", 'recommendations')

    def checkUIDProcs(self):
        self.result.insert('end', '\n{}\n\n'.format('Анализ процессов c различными UID и EUID'), 'title')
        self.result.update()
        vulnerable = False
        euids = command_seq('sudo ps -eo euser', self.password)[0].split('\n')
        uids = command_seq('sudo ps -eo ruser', self.password)[0].split('\n')
        procs = command_seq('sudo ps -e')[0].split('\n')

        for i in range(1, len(euids)):
            if euids[i] != uids[i]:
                vulnerable = True
                self.result.insert('end', 'Процесс {0} имеет различные UID и EUID'.format(procs[i]))
        
        if vulnerable:
            self.result.insert('end', "Рекомендация:\n"
		        + "Необходимо проанализировать данные процессы и, если необходимо завершить командой pkill\n", 'recommendations')
        else:
            self.result.insert('end', "Процессы с различными UID и EUID не обнаружены\n", 'clear')
       
    def checkGIDProcs(self):
        self.result.insert('end', '\n{}\n\n'.format('Анализ процессов c различными GID и EGID'), 'title')
        self.result.update()
        vulnerable = False
        egids = command_seq('sudo ps -eo egroup', self.password)[0].split('\n')
        gids = command_seq('sudo ps -eo rgroup', self.password)[0].split('\n')
        procs = command_seq('sudo ps -e')[0].split('\n')

        for i in range(1, len(egids)):
            if egids[i] != gids[i]:
                vulnerable = True
                self.result.insert('end', 'Процесс {0} имеет различные GID и EGID\n'.format(procs[i]))
        
        if vulnerable:
            self.result.insert('end', "Рекомендация:\n"
		        + "Необходимо проанализировать данные процессы и, если необходимо завершить командой pkill\n", 'recommendations')
        else:
            self.result.insert('end', "Процессы с различными GID и EGID не обнаружены\n", 'clear')
    
# def checkChrootProcs(self):
    #     self.result.insert('end', '\n{}\n\n'.format('Анализ процессов ограниченных chroot'), 'title')
    #     self.result.update()
    #     vulnerable = False
    #     egids = command_seq('sudo ps -eo egroup', self.password)[0].split('\n')
    #     gids = command_seq('sudo ps -eo rgroup', self.password)[0].split('\n')
    #     procs = command_seq('sudo ps -e')[0].split('\n')

    #     for i in range(1, len(egids)):
    #         if egids[i] != gids[i]:
    #             vulnerable = True
    #             self.result.insert('end', 'Процесс {0} имеет различные GID и EGID\n'.format(procs[i]))
        
    #     if vulnerable:
    #         self.result.insert('end', "Рекомендация:\n"
	# 	        + "Необходимо проанализировать данные процессы и, если необходимо завершить командой pkill\n", 'recommendations')
    #     else:
    #         self.result.insert('end', "Процессы с различными GID и EGID не обнаружены\n", 'clear')
    

    def checkATD(self):
        self.result.insert('end', '\n{}\n\n'.format('Анализ файлов atd'), 'title')
        self.result.update()
        vulnerable = False

        allow = command_seq('sudo ls -l /etc/at.allow', self.password)
        deny = command_seq('sudo ls -l /etc/at.deny', self.password)

        if deny[1] != '':
            self.result.insert('end', "Файл /etc/at.deny отсутствует. Любой пользователь может использовать atd\n", 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Создайте файл /etc/at.deny с помощью touch и установите режим доступа 640\n", 'recommendations')
        else:
            deny_stats = deny[0].split()
            if  deny_stats[0] != '-rw-r-----' or deny_stats[2] != 'root' or deny_stats[3] != 'daemon':
                self.result.insert('end', "Файл /etc/at.deny имеет" 
                    + "режим доступа ({0},{1},{2}) отличный от рекомендуемых (-rw-r-----, root, daemon).\n"
                .format(deny_stats[0], deny_stats[2], deny_stats[3]), 'recommendations')
                self.result.insert('end', "Рекомендация:\n"
		            + "Измените режим доступа файла /etc/at.deny на рекомендуемые с помощью команды chmod, " 
                    + "chown и chgrp\n", 'recommendations')
            else:
                deny_file = command_seq('sudo cat /etc/at.deny', self.password)[0]
                self.result.insert('end', 'Содержимое файла /etc/at.deny:\n')
                self.result.insert('end', deny_file)

        if allow[1] != '':
            self.result.insert('end', "\nФайл /etc/at.allow отсутствует.\n", 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Создайте файл /etc/at.allow с помощью touch и установите режим доступа 640\n", 'recommendations')
        else:
            allow_stats = allow[0].split()
            if  allow_stats[0] != '-rw-r-----' or allow_stats[2] != 'root' or allow_stats[3] != 'daemon':
                self.result.insert('end', "Файл /etc/at.deny имеет" 
                    + "режим доступа ({0},{1},{2}) отличный от рекомендуемых (-rw-r-----, root, daemon)\n."
                .format(allow_stats[0], allow_stats[2], allow_stats[3]), 'recommendations')
                self.result.insert('end', "Рекомендация:\n"
		            + "Измените режим доступа файла /etc/at.allow на рекомендуемые с помощью команды chmod, " 
                    + "chown и chgrp\n", 'recommendations')
            else:
                allow_file = command_seq('sudo cat /etc/at.allow', self.password)[0]
                self.result.insert('end', 'Содержимое файла /etc/at.allow:\n')
                self.result.insert('end', allow_file)
            

    def checkCrontab(self):
        self.result.insert('end', '\n{}\n\n'.format('Анализ файлов crontab'), 'title')
        self.result.update()
        vulnerable = False

        allow = command_seq('sudo ls -l /etc/cron.allow', self.password)
        deny = command_seq('sudo ls -l /etc/cron.deny', self.password)

        if deny[1] != '':
            self.result.insert('end', "Файл /etc/cron.deny отсутствует. Любой пользователь может использовать crontab\n", 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Создайте файл /etc/cron.deny с помощью touch и установите режим доступа 640\n", 'recommendations')
        else:
            deny_stats = deny[0].split()
            if  deny_stats[0] != '-rw-r-----' or deny_stats[2] != 'root' or deny_stats[3] != 'daemon':
                self.result.insert('end', "Файл /etc/cron.deny имеет" 
                    + "режим доступа ({0},{1},{2}) отличный от рекомендуемых (-rw-r-----, root, daemon).\n"
                .format(deny_stats[0], deny_stats[2], deny_stats[3]), 'recommendations')
                self.result.insert('end', "Рекомендация:\n"
		            + "Измените режим доступа файла /etc/cron.deny на рекомендуемые с помощью команды chmod, " 
                    + "chown и chgrp\n", 'recommendations')
            else:
                deny_file = command_seq('sudo cat /etc/cron.deny', self.password)[0]
                self.result.insert('end', 'Содержимое файла /etc/cron.deny:\n')
                self.result.insert('end', deny_file)
        
        if allow[1] != '':
            self.result.insert('end', "\nФайл /etc/cron.allow отсутствует.\n", 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Создайте файл /etc/cron.allow с помощью touch и установите режим доступа 640\n", 'recommendations')
        else:
            allow_stats = allow[0].split()
            if  allow_stats[0] != '-rw-r-----' or allow_stats[2] != 'root' or allow_stats[3] != 'daemon':
                self.result.insert('end', "Файл /etc/cron.deny имеет" 
                    + "режим доступа ({0},{1},{2}) отличный от рекомендуемых (-rw-r-----, root, daemon)\n."
                .format(allow_stats[0], allow_stats[2], allow_stats[3]), 'recommendations')
                self.result.insert('end', "Рекомендация:\n"
		            + "Измените режим доступа файла /etc/cron.allow на рекомендуемые с помощью команды chmod, " 
                    + "chown и chgrp\n", 'recommendations')
            else:
                allow_file = command_seq('sudo cat /etc/cron.allow', self.password)[0]
                self.result.insert('end', 'Содержимое файла /etc/cron.allow:\n')
                self.result.insert('end', allow_file)
            

    def checkCrontabFiles(self):
        self.result.insert('end', '\n{}\n\n'.format('Задачи crontab'), 'title')
        self.result.update()
        vulnerable = False

        hourly = command_seq('sudo ls -1 /etc/cron.hourly', self.password)[0].replace('\n', '\n\t')
        daily = command_seq('sudo ls -1 /etc/cron.daily', self.password)[0].replace('\n', '\n\t')
        weekly = command_seq('sudo ls -1 /etc/cron.weekly', self.password)[0].replace('\n', '\n\t')
        monthly = command_seq('sudo ls -1 /etc/cron.monthly', self.password)[0].replace('\n', '\n\t')

        if hourly != '':
            vulnerable = True
            self.result.insert('end', '\nЗадачи, выполняемые каждый час:\n{0}'.format('\t' + hourly))
        else:
            self.result.insert('end', '\nЗадачи, выполняемые каждый час, отсутствуют\n', 'clear')

        if daily != '':
            vulnerable = True
            self.result.insert('end', '\nЗадачи, выполняемые каждый день:\n{0}'.format('\t' + daily))
        else:
            self.result.insert('end', '\nЗадачи, выполняемые каждый день, отсутствуют\n', 'clear')
        
        if weekly != '':
            vulnerable = True
            self.result.insert('end', '\nЗадачи, выполняемые каждую неделю:\n{0}'.format('\t' + weekly))
        else:
            self.result.insert('end', '\nЗадачи, выполняемые каждую неделю, отсутствуют\n', 'clear')

        if monthly != '':
            vulnerable = True
            self.result.insert('end', '\nЗадачи, выполняемые каждый месяц:\n{0}'.format('\t' + monthly))
        else:
            self.result.insert('end', '\nЗадачи, выполняемые каждый месяц отсутствуют\n', 'clear')
        
        if vulnerable:
            self.result.insert('end', "\nРекомендация:\n"
		        + "Проанализируйте содержимое задач и убедитесь, что они безопасны, иначе удалите их\n", 'recommendations')