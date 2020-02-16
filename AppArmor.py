import datetime
import tkinter as tk
import tkinter.ttk as ttk
from commands import *
from Log import write_log


class AppArmor_Tab(object):
    def __init__(self, master):

        self.password = ''
        self.aa_users = dict()
        self.aa_groups = dict()
        self.aa_status = False

        self.base_profiles = ['/usr/bin/chromium-browser', '/usr/bin/opera', '/usr/bin/firefox',
                              '/usr/sbin/useradd', '/usr/sbin/userdel', '/usr/bin/passwd',
                              '/sbin/syslogd', '/usr/lib/postix/flush', '/usr/lib/postfix/pipe',
                              '/usr/lib/dovecot/imap-login', '/usr/lib/dovecot/pop3-login',
                              '/usr/sbin/sendmail', '/sbin/dhclient', '/usr/sbin/dhcpd',
                              '/sbin/dhcpcd', '/usr/bin/xfs', '/usr/sbin/in/ftpd', '/usr/sbin/smbd',
                              '/usr/sbin/sshd', '/bin/ping', '/bin/netstat', '/usr/sbin/dnsmasq',
                              '/usr/sbin/traceroute', '/usr/sbin/xinetd']

        self.s = []
        self.vars = [tk.IntVar(), tk.IntVar(), tk.IntVar(), tk.IntVar()]
        for p in self.vars:
            p.set(1)

        frame = ttk.LabelFrame(master, text='Результат аудита системы AppArmor')
        conf_frame = ttk.Frame(master, width=260)

        self.result = tk.Text(frame, wrap='word', height=36)

        self.result.tag_configure('title', font=('Verdana', 12), justify='center')

        self.chb_status = ttk.Checkbutton(conf_frame, text='Проверка статуса AppArmor',
                                          variable=self.vars[0], onvalue=1, offvalue=0)
        self.chb_sysprofiles = ttk.Checkbutton(conf_frame, text='Проверка системных профилей',
                                               variable=self.vars[1], onvalue=1, offvalue=0)
        self.chb_unconfined = ttk.Checkbutton(conf_frame, text='Выявление сетевых процессов\n с открытыми tcp и udp портами\n не имеющих профилей',
                                              variable=self.vars[2], onvalue=1, offvalue=0)
        self.chb_logs = ttk.Checkbutton(conf_frame, text='Анализ журнала аудита AppArmor',
                                        variable=self.vars[3], onvalue=1, offvalue=0)

        self.btn_run = ttk.Button(conf_frame, text='Запуск аудита', command=self.run_audit)

        self.ytext = ttk.Scrollbar(frame, orient='vertical', command=self.result.yview)
        self.result.configure(yscroll=self.ytext.set)

        ttk.Style().configure('Treeview', rowheight=30)
        ttk.Style().configure('Vertical.TScrollbar', troughcolor='#f6f4f2', relief=tk.GROOVE)
        ttk.Style().configure('Horizontal.TScrollbar', troughcolor='#f6f4f2')

        conf_frame.pack(side=tk.LEFT, anchor='n', fill=tk.Y)
        sep = ttk.Separator(master, orient='vertical').pack(side=tk.LEFT, anchor='n', fill=tk.Y)
        frame.pack(side=tk.LEFT, anchor='n', fill=tk.BOTH, expand=1)

        self.btn_run.pack(side=tk.BOTTOM, pady=5, padx=5, anchor='s', fill=tk.X)
        self.chb_status.pack(anchor='w', padx=5, pady=1)
        self.chb_sysprofiles.pack(anchor='w', padx=5, pady=0)
        self.chb_unconfined.pack(anchor='w', padx=5, pady=0)
        self.chb_logs.pack(anchor='w', padx=5, pady=0)

        self.ytext.pack(side=tk.RIGHT, anchor='n', fill=tk.Y)
        self.result.pack(side=tk.TOP, fill=tk.BOTH, anchor='nw')

    def set_pass(self, pas):
        self.password = pas

    def run_audit(self):
        self.result.delete('1.0', 'end')
        beginning = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S\n\n')
        self.result.insert('end', ' Начало аудита системы AppArmor:    ' + str(beginning))
        self.result.update()
        funcs = [self.check_status, self.check_sysprofiles, self.check_unconfined, self.check_logs]

        for var in range(0, len(self.vars)):
            if self.vars[var].get() == 1:
                funcs[var]()
                self.result.see('end')

        ending = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S\n')
        self.result.insert('end', '\n Окончание аудита системы AppArmor: ' + str(ending))
        self.result.see('end')

        write_log(self.result.get('1.0', 'end'))

    def check_status(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка статуса AppArmor'), 'title')
        self.result.update()

        status = command_seq('sudo apparmor_status', self.password)
        if 'apparmor module is loaded.' in status[0]:
            self.aa_status = True
            self.result.insert('end', status[0])
        else:
            self.result.insert('end', '{}\n'.format('Модуль AppArmor остановлен или отсутствует'))
            self.result.insert("Рекомендация:\n"
		        + "Настройте AppArmor при помощи установки соответствующих пакетов и библиотек.\n\n") 
        return

    def check_sysprofiles(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка основных системных профилей AppArmor'), 'title')
        self.result.update()

        status = command_seq('sudo apparmor_status', self.password)[0].split('\n')
        if 'apparmor module is loaded.' == status[0]:
            vulnerable = False
            enforce_profiles = command_seq('sudo cat /sys/kernel/security/apparmor/profiles | grep -s enforce', self.password)
            complain_profiles = command_seq('sudo cat /sys/kernel/security/apparmor/profiles | grep -s complain', self.password)
            for profile in self.base_profiles:
                if profile not in enforce_profiles[0]:
                    if profile not in complain_profiles[0]:
                        vulnerable = True
                        self.result.insert('end', ' Базовый профиль {} не обнаружен\n'.format(profile))
                    else:
                        vulnerable = True
                        self.result.insert('end', ' Профиль {} находится в режиме обучения.'
                                                  ' Рекомендуется перевести его в режим ограничения\n'.format(profile))

            if not vulnerable:
                self.result.insert('end', '{}\n'.format('Все основные профили загружены и настроены'))
        else:
            self.result.insert('end', '{}\n'.format('Модуль AppArmor остановлен или отсутствует'), 'title')
            self.result.insert("Рекомендация:\n"
		        + "Настройте AppArmor при помощи установки соответствующих пакетов и библиотек и проверьте наличие необходимых модулей\n\n") 

        return

    def check_unconfined(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка сетевых процессов, не имеющих загруженных профилей AppArmor'), 'title')
        self.result.update()

        status = command_seq('sudo apparmor_status', self.password)[0].split('\n')
        if 'apparmor module is loaded.' == status[0]:
            unconfined_profiles = command_seq('sudo aa-unconfined', self.password)[0]
            self.result.insert('end', unconfined_profiles)
        else:
            self.result.insert('end', '{}\n'.format('Модуль AppArmor остановлен или отсутствует'))
            self.result.insert("Рекомендация:\n"
		        + "Настройте AppArmor при помощи установки соответствующих пакетов и библиотек.\n"
                + "Убедитесь, что необходимые профили загружены и включены.\n\n") 
        return

    def check_logs(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка журнала аудита AppArmor'), 'title')
        self.result.update()

        status = command_seq('sudo apparmor_status', self.password)[0].split('\n')
        if 'apparmor module is loaded.' == status[0]:
            logs = command_seq('sudo cat /var/log/kern.log | grep -s apparmor', self.password)[0].replace('\n', '\n  ')
            self.result.insert('end', logs)
        else:
            self.result.insert('end', '{}\n'.format(' Модуль AppArmor остановлен или отсутствует'))
            self.result.insert('end', "Рекомендация:\n"
		        + "Включите AppArmor если он отключен или настройте его при помощи установки соответствующих пакетов и библиотек.\n\n") 
        return