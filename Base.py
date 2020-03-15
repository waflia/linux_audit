from commands import command_seq

from API import Module


class Base_Tab(Module):
    def __init__(self, master, path):
        super().__init__(master, True)

        self.sys_dirs = {'/etc/passwd':         'rw-r--r--',
                         '/etc/shadow':         'rw-------',
                         '/etc/hosts.allow':    'rw-------',
                         '/etc/hosts.deny':     'rw-------',
                         '/etc/logrotate.conf': 'rw-r-----',
                         '/etc/rsyslog.conf':   'rw-r-----',
                         '/etc/pam.d':          'rwxr-x---',
                         '/etc/securetty':      'rw-------',
                         '/etc/security':       'rw-------',
                         '/etc/init.d':         'rwxr-x---',
                         '/var/log':            'rwxr-x--x'}
        
        self.functions = {"Маска":self.check_mask,
                    "Полные права": self.check_fullpermissions,
                    "Права владельца": self.check_owner_permissions,
                    "Системные файлы": self.check_system,
                    "Файлы без прав":self.check_none_permissions,
                    "Невидимые файлы": self.check_unvisible,
                    "Nobody,Nogroup": self.check_none_og,
                    "Suid": self.check_suid,
                    "Sgid": self.check_sgid,
                    "Sticky": self.check_sticky}
        
        self.setFuncs(self.functions)
        self.setParams(header = "базовой СКД")

    def check_mask(self):
        self.result.insert('end', '{text}\n\n'.format(text='Проверка текущей маски'), 'title')
        self.result.update()
        umask = command_seq('sudo cat /etc/login.defs | grep UMASK', self.password)[0].split('\n')
        self.result.insert('end', ' Текущая маска пользователя: {}\n'.format(umask[-2]))
        return

    def check_fullpermissions(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск объектов с полными правами для категории "Все остальные"'), 'title')
        self.result.update()
        vulnerable = False
        for file in self.files.keys():
            if 'rwx' == self.files[file][0][7:10] or 'rwt' == self.files[file][0][7:10]:
                self.result.insert('end', ' {} : {}\n'.format(file, self.files[file][0]))
                vulnerable = True
        if not vulnerable:
            self.result.insert('end', ' Объекты с полными правами для категории "Все остальные" не обнаружены\n')
        else:
            self.result.insert('end', "\nРекомендация:\n"
	        + "Необходимо исключить полный доступ постановкой на каталоги прав 755 ,\n"
            + " у файлов - прав 644 .\n" 
            +"Либо поставить любую другую комбинацию прав, не нарушающую безопасности данного объекта и общей безопасности системы.\n\n" )
        return

    def check_owner_permissions(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск объектов с неправильно настроенными правами владельца'), 'title')
        self.result.update()
        vulnerable = False
        for file in self.files.keys():
            owner_pers = self.files[file][0][1:4]
            group_pers = self.files[file][0][4:7]
            other_pers = self.files[file][0][7:10]

            for i in range(3):
                if owner_pers[i] == '-' or owner_pers[i] == 'S':
                    if (group_pers[i] != '-' and group_pers[i] != 'S') or (other_pers[i] != '-' and other_pers[i] != 'T'):
                        self.result.insert('end', ' {}: {}\n'.format(file, self.files[file][0]))
                        vulnerable = True
                        break
        if not vulnerable:
            self.result.insert('end', ' Объекты с неправильно настроенными правами владельца не обнаружены\n')
        else:
            self.result.nsert('end', "\nРекомендация:\n"
	        + "Необходимо установить правильные права владельца на объект,\n"
            +"Либо поставить любую другую комбинацию прав, не нарушающую безопасности данного объекта и общей безопасности системы.\n\n" )
        return

    def check_system(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Проверка режима доступа важных системных объектов'), 'title')
        self.result.update()
        vulnerable = False
        for dir in self.sys_dirs.keys():
            current_per = command_seq('ls -ld {}'.format(dir))[0].split('\n')[0].split(' ')[0][1:11]
            if current_per != self.sys_dirs[dir]:
                self.result.insert('end', ' Права объекта: {}:{} отличны от рекомендуемых: {}\n'.format(dir, current_per, self.sys_dirs[dir]))
                vulnerable = True

        if not vulnerable:
            self.result.insert('end', ' Режимы доступа системных объектов соответствуют рекомендуемым\n')
        else:
            self.result.insert('end', "\nРекомендация:\n"
	        + "Убедитесь, что режимы доступа системных объектов не создают потенциальных угроз.\n"
            +"Если необходимо, то измените их на рекомендуемые.\n\n" )
        return

    def check_none_permissions(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Проверка необходимых прав доступа к объектам'), 'title')
        self.result.update()
        vulnerable = False
        for file in self.files.keys():
            object_per = self.files[file][0]
            if object_per[0] == 'd':
                if object_per[3] == '-' or object_per[3] == 'S':
                    self.result.insert('end', ' Каталог {} не имеет необходимых прав доступа для владельца: {}\n'.format(file, object_per))
                    vulnerable = True
            else:
                if object_per[1] == '-':
                    self.result.insert('end', ' Файл {} не имеет прав на чтение для владельца: {}\n'.format(file, object_per))
                    vulnerable = True

        if not vulnerable:
            self.result.insert('end', ' Права доступа к объектам не нарушены\n')
        else:
            self.result.insert('end', "\nРекомендация:\n"
	        + "Необходимо проверить режимы доступа объектов на доступность файлов и каталогов\n"
            +"Если необходимо, то измените режимы доступа с помощью команд chmod <perms> object.\n\n" )
        return

    def check_unvisible(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Проверка необходимых прав на чтение каталогов для владельца'), 'title')
        self.result.update()
        vulnerable = False
        for file in self.files.keys():
            object_per = self.files[file][0]
            if object_per[0] == 'd':
                if object_per[1] == '-':
                    self.result.insert('end',
                                       ' Каталог {} не имеет необходимых прав на чтение для владельца: {}\n'.format(file, object_per))
                    vulnerable = True

        if not vulnerable:
            self.result.insert('end', ' Необходимые права на чтение каталогов не нарушены\n')
        else:
            self.result.nsert('end', "\nРекомендация:\n"
	        + "Необходимо исключить полный доступ постановкой на каталоги прав 755 ,\n"
            + " у файлов - прав 644 .\n" 
            +"Либо поставить любую другую комбинацию прав, не нарушающую безопасности данного объекта и общей безопасности системы.\n\n" )
        return

    def check_none_og(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск объектов с владельцем "nobody" и группой владельца "nogroup"'), 'title')
        self.result.update()
        vulnerable = False
        for dir in self.files.keys():
            owner = self.files[dir][2]
            group = self.files[dir][3]
            if owner == 'nobody':
                if group == 'nogroup':
                    self.result.insert('end', ' Объект {} имеет владельца "nobody" и группу "nogroup"\n'.format(dir))
                else:
                    self.result.insert('end', ' Объект {} имеет владельца "nobody"\n'.format(dir))
                vulnerable = True
            elif group == 'nogroup':
                self.result.insert('end', ' Объект {} имеет группу "nogroup"\n'.format(dir))
                vulnerable = True

        if not vulnerable:
            self.result.insert('end', ' Объекты без владельца и группы не обнаружены\n')
        else:
            self.result.insert('end', "\nРекомендация:\n"
	        + 'Необходимо установить объектам владельца отдельного от "nobody" и группы "nogroup"\n'
            + 'с помощью команды chown <user> object и chgrp <group> object.\n\n' )
        return

    def check_suid(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск объектов с SUID-битом'), 'title')
        self.result.update()
        vulnerable = False
        for dir in self.files.keys():
            per = self.files[dir][0]
            if per[3] == 's' or per[3] == 'S':
                self.result.insert('end', ' У объекта {} установлен SUID-бит: {}\n'.format(dir, per))
                vulnerable = True

        if not vulnerable:
            self.result.insert('end', ' Объекты с SUID-битом не обнаружены\n')
        else:
            self.result.nsert('end', "\nРекомендация:\n"
	        + "Убедитесь, что SUID-бит необходим и не нарушает безопасности системы.\n"
            + "Либо установите любую другую комбинацию прав, не нарушающую безопасности данного объекта и общей безопасности системы.\n\n" )
        return

    def check_sgid(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск объектов со SGID-битом'), 'title')
        self.result.update()
        vulnerable = False
        for dir in self.files.keys():
            per = self.files[dir][0]
            if per[6] == 's' or per[6] == 'S':
                self.result.insert('end', ' У объекта {} установлен SGID-бит: {}\n'.format(dir, per))
                vulnerable=True

        if not vulnerable:
            self.result.insert('end', ' Объекты со SGID-битом не обнаружены\n')
        else:
            self.result.nsert('end', "\nРекомендация:\n"
	        + "Убедитесь, что SGID-бит необходим и не нарушает безопасности системы.\n"
            + "Либо установите любую другую комбинацию прав, не нарушающую безопасности данного объекта и общей безопасности системы.\n\n" )
        return

    def check_sticky(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск объектов со Sticky-битом'), 'title')
        self.result.update()
        vulnerable = False
        for dir in self.files.keys():
            per = self.files[dir][0]
            if per[9] == 't' or per[9] == 'T':
                self.result.insert('end', ' У объекта {} установлен Sticky-бит: {}\n'.format(dir, per))
                vulnerable = True

        if not vulnerable:
            self.result.insert('end', ' Объекты со Sticky-битом не обнаружены\n')
        else:
            self.result.nsert('end', "\nРекомендация:\n"
	        + "Убедитесь, что Sticky-бит необходим и не нарушает безопасности системы.\n"
            + "Либо установите любую другую комбинацию прав, не нарушающую безопасности данного объекта и общей безопасности системы.\n\n" )
        return