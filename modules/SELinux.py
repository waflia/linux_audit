from API import Module
from commands import *

class SELinux_Tab(Module):

    def __init__(self, master):
        super().__init__(master, False)
        self.functions = {
            "Статус SELinux \nв системе": self.checkSELinuxStatus,
            "Режим работы SELinux": self.checkSELinuxMode,
            "Контексты SELinux \nдля каталогов":self.checkSELinuxFolders,
            "Контексты SELinux \nдля процессов": self.checkSELinuxProcesses,
            "Контексты пользователей": self.checkSELinuxUsers,
            "Активность политик \nSELinux": self.checkSELinuxPolitics,
            "Защита портов\n с помощью SELinux": self.checkSELinuxPorts,
            "Анализ журнала\n событий SELinux" : self.checkSELinuxLogs
        }
        self.setFuncs(self.functions)
        self.setParams(header = "модуля SELinux")
    
    def checkSELinuxMode(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка режима работы SELinux'), 'title')
        self.result.update()

        status = command_seq('sudo sestatus', self.password)
        if 'SELinuxstatus:enabled' not in status[0].replace(' ', ''):
            self.result.insert('end', '{}\n'.format('Внимание! Модуль SELinux в данной системе ' 
            + 'не настроен или отсутствует.\n'), 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Настройте SELinux при помощи установки соответствующих пакетов и библиотек.\n\n", 'recommendations') 
        else:
            command_result = command_seq('sudo getenforce')
            if 'enforcing' in command_result[0]:
                self.result.insert('end', '{}\n'.format("SELinux находится в режиме enforced. Система защищена\n"), 'clear')
            elif 'permissive' in command_result[0]:
                self.result.insert('end', '{}\n'.format("Внимание! SELinux находится в режиме регистрации событий безопасности!\n"), 'recommendations')
                self.result.insert('end', "Рекомендация:\n"
                + "Если система не должна находиться в тестовом режиме, то необходимо сменить режим на enforce.\n\n ", 'recommendations')
            elif 'disabled' in command_result[0]:
                self.result.insert('end', '{}\n'.format("Уязвимость! SELinux в системе неактивен!\n"), 'warning')
                self.result.insert('end', "Рекомендация:\n"
		        + "Активируйте работу SELinux путем установки режима permissive для тестировки или enforce для работы с системой.\n\n", 'recommendations') 
        return

    def checkSELinuxStatus(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка статуса SELinux'), 'title')
        self.result.update()

        status = command_seq('sudo sestatus', self.password)
        if 'SELinuxstatus:enabled' in status[0].replace(' ', ''):
            self.result.insert('end', status[0])
        else:
            self.result.insert('end', '{}\n'.format('Внимание! Модуль SELinux в данной системе не настроен или отсутствует.\n'), 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Настройте SELinux при помощи установки соответствующих пакетов и библиотек.\n\n", 'recommendations') 
        return

    def checkSELinuxFolders(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка политик SELinux для главных системных файлов'), 'title')
        self.result.update()

        status = command_seq('sudo sestatus', self.password)
        if 'SELinuxstatus:enabled' not in status[0].replace(' ', ''):
            self.result.insert('end', '{}\n'.format('Внимание! Модуль SELinux в данной системе не настроен или отсутствует.\n'), 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Настройте SELinux при помощи установки соответствующих пакетов и библиотек.\n\n", 'recommendations') 
        else:
            command_result = command_seq('sudo getenforce')
            if 'enforcing' in command_result[0]:
                pass
            elif 'permissive' in command_result[0]:
                pass
            elif 'disabled' in command_result[0]:
                self.result.insert('end', '%\n'.format("Уязвимость! SELinux в системе неактивен!\n"), 'warning')
                self.result.insert('end', "Рекомендация:\n"
		        + "Активируйте работу SELinux путем установки режима permissive для" 
                + "тестировки или enforce для работы с системой.\n\n", 'recommendations') 
        return
    
    def checkSELinuxProcesses(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка политик SELinux для процессов'), 'title')
        self.result.update()
        status = command_seq('sudo sestatus', self.password)

        if 'SELinuxstatus:enabled' not in status[0].replace(' ', ''):
            self.result.insert('end', '{}\n'.format('Внимание! Модуль SELinux в данной системе не настроен или отсутствует.\n'), 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Настройте SELinux при помощи установки соответствующих пакетов и библиотек.\n\n", 'recommendations') 
        else:
            command_result = command_seq('ps -eZ| grep -s root')
            self.result.insert('end', '{}\n'.format("Важные процессы в системе работающие от имени root:\n{}\n".
            format(command_result)))
            self.result.insert('end', "Рекомендация:\n"
		        + "Убедитесь в корректной работе данных процессов и при необходимости примите меры.\n\n", 'recommendations') 
        return

    def checkSELinuxUsers(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка политик SELinux для пользователей'), 'title')
        self.result.update()
        status = command_seq('sudo sestatus', self.password)

        if 'SELinuxstatus:enabled' not in status[0].replace(' ', ''):
            self.result.insert('end', '{}\n'.format('Внимание! Модуль SELinux в данной системе не настроен или отсутствует.\n'), 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Настройте SELinux при помощи установки соответствующих пакетов и библиотек.\n\n", 'recommedations') 
        else:
            command_result = command_seq('semanage login -l')
            self.result.insert('end', '{}\n'.format("Контексты SELinux для пользователей активных в системе:\n{}\n".
            format(command_result)))
        return

    def checkSELinuxPolitics(self):
        self.result.insert('end', '\n{}\n\n'.format('Активность политик SELinux'), 'title')
        self.result.update()
        status = command_seq('sudo sestatus', self.password)

        if 'SELinuxstatus:enabled' not in status[0].replace(' ', ''):
            self.result.insert('end', '{}\n'.format('Внимание! Модуль SELinux в данной системе не настроен или отсутствует.\n'), 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Настройте SELinux при помощи установки соответствующих пакетов и библиотек.\n\n", 'recommendations') 
        else:
            command_result = command_seq('exec getsebool -a | grep -v off')
            self.result.insert('end', '{}\n'.format("Активные политики безопасности SELinux:\n{}\n".
            format(command_result)))
            
            command_result = command_seq('exec getsebool -a | grep -s off')
            self.result.insert('end', '{}\n'.format("Отключенные политики безопасности SELinux:\n{}\n".
            format(command_result)))
            self.result.insert('end', "Рекомендация:\n"
		        + "Проверьте отключенные профили и включите их, если это необходимо для безопасности системы.\n\n", 'recommendations') 
        return

    def checkSELinuxPorts(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка политик SELinux для сетевых портов'), 'title')
        self.result.update()
        status = command_seq('sudo sestatus', self.password)

        if 'SELinuxstatus:enabled' not in status[0].replace(' ', ''):
            self.result.insert('end', '{}\n'.format('Внимание! Модуль SELinux в данной системе не настроен или отсутствует.\n'), 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Настройте SELinux при помощи установки соответствующих пакетов и библиотек.\n\n", 'recommendations') 
        else:
            command_result = command_seq('semanage port -l')
            self.result.insert('end', '{}\n'.format("Порты:\n{}\n".
            format(command_result)))
            self.result.insert('end', "Рекомендация:\n"
		        + "Активировать профили SELinux, необходимые для безопасности портов системы.\n\n", 'recommedations') 
        return

    def checkSELinuxLogs(self):
        self.result.insert('end', '\n{}\n\n'.format('Просмотр журнала аудита безопасности SELinux'), 'title')
        self.result.update()
        status = command_seq('sudo sestatus', self.password)

        if 'SELinuxstatus:enabled' not in status[0].replace(' ', ''):
            self.result.insert('end', '{}\n'.format('Внимание! Модуль SELinux в данной системе не настроен или отсутствует.\n'), 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Настройте SELinux при помощи установки соответствующих пакетов и библиотек.\n\n", 'recommendations') 
        else:
            command_result = command_seq('sudo cat < /var/log/audit/audit.log')
            self.result.insert('end', '{}\n'.
            format(command_result))
            self.result.insert('end', "Рекомендация:\n"
		        + "Проанализируйте информацию последнего аудита событий SELinux и сделайте выводы о текущих уязвимостях.\n\n", 'recommendations') 
        return