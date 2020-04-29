import os
import datetime
from commands import *

from API import Module

class ACL_Tab(Module):
    def __init__(self, master, path='/'):
        super().__init__(master, True)

        self.functions = {
            "Поиск файлов с ACL": self.check_acl,
            "Файлы с полными правами\n для пользователя и группы": self.check_fullpermissions,
            "Файлы с неправильными\n правами владельца": self.check_owner_permissions,
            "Проверка ошибок при\n установке прав ACL": self.check_err
            }   

        self.setFuncs(self.functions)
        self.setParams(header = "списков ACL")
    
    def check_acl(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск объектов с правами ACL\n Угроза:потенциальная уязвимость'), 'title')
        self.result.update()

        vulnerable = False
        for file in self.files.keys():
            per = self.files[file][0]
            if '+' in per:
                acl_pers = command_seq('getfacl {}'.format(file))[0].split('\n')
                acl = ''
                for pers in acl_pers:
                    acl = acl + '\n   ' + pers
                self.result.insert('end', ' Объект {} имеет расширенные права ACL: {}\n'.format(file, acl))
                vulnerable = True
        if not vulnerable:
            self.result.insert('end', ' Объекты с правами ACL не обнаружены\n', 'clear')
            self.result.insert('end', "\n Рекомендация: Действий не требуется\n", 'recommendations')
        else:
            self.result.insert('end', " Рекомендация:\nУбедитесь, что права ACL на данные объекты необходимы.\n"  
                               + " В противном случае удалите или измените их на комбинацию," 
                               + " не нарушающую безопасности системы, командой:\n" 
                                + " setfacl -m u:username:rwx obj_name.\n\n", 'recommendations')
        return

    def check_fullpermissions(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка наличия полного доступа по маске ACL'), 'title')
        self.result.update()
        vulnerable = False
        for file in self.files.keys():
            per = self.files[file][0]
            if '+' in per:
                acl_mask = command_seq('getfacl {} | grep -s mask::'.format(file))[0].split('\n')
                acl_pers = command_seq('getfacl {}'.format(file))[0].split('\n')
                if 'rwx' in acl_mask[0]:
                    acl = ''
                    for pers in acl_pers:
                        acl = acl + '\n   ' + pers
                    self.result.insert('end', ' Объект {} имеет полную маску доступа ACL : {}\n'.format(file, acl))
                    vulnerable = True
        if not vulnerable:
            self.result.insert('end', ' Объекты c полным доступом по маске ACL не обнаружены\n', 'clear')
            self.result.insert('end', "\n Рекомендация: Действий не требуется\n", 'recommendations')
        else:
            self.result.insert('end', " Рекомендация:\nУбедитесь, что наличие полного доступа по маске не нарушает безопасности системы.\n"  
                               + " В противном случае удалите или измените маску ACL на комбинацию," 
                               + " не нарушающую безопасности системы, командой:\n" 
                                + " setfacl -m m:rwx obj_name.\n\n", 'recommendations')
        return

    def check_owner_permissions(self):
        self.result.insert('end', '\n{}\n\n'.format('Поиск объектов с полными правами ACL для субъекта и группы-субъекта'), 'title')
        self.result.update()
        vulnerable = False
        for file in self.files.keys():
            per = self.files[file][0]
            if '+' in per:
                owner = self.files[file][2]
                group = self.files[file][3]
                acl_pers = command_seq('getfacl {}'.format(file))[0].split('\n')
                for row in acl_pers:
                    current = row.split(':')
                    if (current[0] == 'user') and ('rwx' in current) and (owner != current[1]) and (current[1] != ''):
                        acl = ''
                        for pers in acl_pers:
                            acl = acl + '\n   ' + pers
                        self.result.insert('end', ' Пользователь {} имеет полный доступ к объекту {} : {}\n'.format(current[1], file, acl))
                        vulnerable = True

                    if (current[0] == 'group') and ('rwx' in current) and (group != current[1]) and (current[1] != ''):
                        acl = ''
                        for pers in acl_pers:
                            acl = acl + '\n   ' + pers
                        self.result.insert('end', ' Группа {} имеет полный доступ к объекту {} : {}\n'.format(
                            current[1], file, acl))
                        vulnerable = True
        if not vulnerable:
            self.result.insert('end', ' Объекты с полными правами доступа ACL не обнаружены\n', 'clear')
            self.result.insert('end', "\n Рекомендация: Действий не требуется\n", 'recommendations')
        else:
            self.result.insert('end', " Рекомендация:\nУбедитесь, что полные права ACL на данные объекты для субъекты и группы необходимы.\n"  
            + " В противном случае удалите или измените их на комбинацию," 
            + " не нарушающую безопасности системы, командой:\n" 
            + " setfacl -m u:username:rwx obj_name\nsetfacl -m g:groupname:rwx obj_name\n\n", 'recommendations')
        return

    def check_err(self):
        self.result.insert('end', '\n{}\n\n'.format('Поиск объектов с неправильно настроенными правами ACL'), 'title')
        self.result.update()
        vulnerable = False
        for file in self.files.keys():
            per = self.files[file][0]
            if '+' in per:
                owner = self.files[file][2]
                group = self.files[file][3]
                acl_pers = command_seq('getfacl {}'.format(file))[0].split('\n')
                error = True
                for row in acl_pers:
                    current = row.split(':')
                    if (current[0] == 'user') or (current[0] == 'group'):
                        if (current[1] != '') and ((current[1] != owner) or (current[1] != group)):
                            error = False

                if error:
                    acl = ''
                    for pers in acl_pers:
                        acl = acl + '\n   ' + pers
                    self.result.insert('end',
                                       ' На объекте {} неправильно настроены права ACL для пользователей: {}\n'.format(
                                       file, acl))
                    vulnerable = True

        if not vulnerable:
            self.result.insert('end', ' Объекты с ошибкой при настройке ACL не обнаружены\n', 'clear')
            self.result.insert('end', "\n Рекомендация: Действий не требуется\n", 'recommendations')
        else:
            self.result.insert('end', "Рекомендация:\nУбедитесь, что права ACL на данные объекты необходимы и установлены правильно.\n"  
                               + "В противном случае удалите или измените их на комбинацию," 
                               + " не нарушающую безопасности системы, командой:\n" 
                                + "setfacl -m u:username:rwx obj_name.\n\n", 'recommendations')
        return