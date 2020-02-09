import os
import datetime
import tkinter as tk
import tkinter.ttk as ttk
from commands import *
from tree import Tree
from Log import write_log


class ACL_Tab(object):
    def __init__(self, master, path):

        self.current_item = ''
        self.nodes = dict()
        self.password = ''
        self.opt = dict()
        self.acl_users = dict()
        self.acl_groups = dict()
        self.changes = ''
        self.files = dict()
        self.s = []

        self.vars = [tk.IntVar(), tk.IntVar(), tk.IntVar(), tk.IntVar()]
        for p in self.vars:
            p.set(1)

        frame = ttk.LabelFrame(master, text='Результат аудита прав ACL')
        conf_frame = ttk.Frame(master, width=270)
        tree_frame = ttk.Frame(conf_frame, width=270)

        self.result = tk.Text(frame, wrap='word', height=36)
        self.result.tag_configure('title', font=('Verdana', 12), justify='center')

        self.chb_search = ttk.Checkbutton(conf_frame, text='Поиск объектов с правами ACL', variable=self.vars[0],
                                          onvalue=1, offvalue=0)
        self.chb_fullpers = ttk.Checkbutton(conf_frame, text='Проверка полного доступа по маске', variable=self.vars[1],
                                            onvalue=1, offvalue=0)
        self.chb_ownpers = ttk.Checkbutton(conf_frame, text='Проверка полного доступа субъекта\n и группы-субъекта',
                                           variable=self.vars[2], onvalue=1, offvalue=0)
        self.chb_err = ttk.Checkbutton(conf_frame, text='Ошибки при настройке прав ACL', variable=self.vars[3],
                                       onvalue=1, offvalue=0)

        self.btn_run = ttk.Button(conf_frame, text='Запуск аудита', command=self.run_audit)

        self.tree = Tree(tree_frame, path=path)

        self.ytext = ttk.Scrollbar(frame, orient='vertical', command=self.result.yview)
        self.result.configure(yscroll=self.ytext.set)

        ttk.Style().configure('Treeview', rowheight=30)
        ttk.Style().configure('Vertical.TScrollbar', troughcolor='#f6f4f2', relief=tk.GROOVE)
        ttk.Style().configure('Horizontal.TScrollbar', troughcolor='#f6f4f2')

        conf_frame.pack(side=tk.LEFT, anchor='n', fill=tk.Y)

        tree_frame.pack(side=tk.TOP, fill=tk.Y, anchor='sw', pady=5, padx=5, expand=1)
        sep = ttk.Separator(master, orient='vertical').pack(side=tk.LEFT, anchor='n', fill=tk.Y)
        frame.pack(side=tk.LEFT, anchor='n', fill=tk.BOTH, expand=1)

        self.chb_search.pack(side=tk.TOP, anchor='nw', padx=5, pady=1)
        self.chb_fullpers.pack(side=tk.TOP, anchor='nw', padx=5, pady=0)
        self.chb_ownpers.pack(side=tk.TOP, anchor='nw', padx=5, pady=0)
        self.chb_err.pack(side=tk.TOP, anchor='nw', padx=5, pady=0)

        self.btn_run.pack(side=tk.BOTTOM, pady=5, padx=5, anchor='s', fill=tk.X)

        self.ytext.pack(side=tk.RIGHT, anchor='n', fill=tk.Y)
        self.result.pack(side=tk.TOP, fill=tk.BOTH, anchor='nw')

        self.abspath = os.path.abspath(path)

    def set_pass(self, pas):
        self.password = pas
        self.tree.set_pass(pas)

    def run_audit(self):
        self.result.delete('1.0', 'end')
        beginning = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S\n\n')
        self.result.insert('end', ' Начало аудита системы ACL:    ' + str(beginning))
        self.result.update()
        self.files = self.tree.file_permissions()

        funcs = [self.check_acl, self.check_fullpermissions, self.check_owner_permissions, self.check_err]

        for var in range(0, len(self.vars)):
            if self.vars[var].get() == 1:
                funcs[var]()
                self.result.see('end')

        ending = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S\n')
        self.result.insert('end', '\n Окончание аудита системы ACL: ' + str(ending))
        self.result.see('end')

        write_log(self.result.get('1.0', 'end'))

    def check_acl(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск объектов с правами ACL'), 'title')
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
            self.result.insert('end', ' Объекты с правами ACL не обнаружены\n')
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
            self.result.insert('end', ' Объекты c полным доступом по маске ACL не обнаружены\n')
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
            self.result.insert('end', ' Объекты с полными правами доступа ACL не обнаружены\n')
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
            self.result.insert('end', ' Объекты с ошибкой при настройке ACL не обнаружены\n')
        return
