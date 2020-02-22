import datetime
import tkinter as tk
import tkinter.ttk as ttk
from commands import *

from API import Module


class net_Tab2(object):
    def __init__(self, master):

        self.password = ''
        self.net_status = False

        self.s = []
        self.vars = [tk.IntVar(), tk.IntVar(), tk.IntVar(), tk.IntVar(), tk.IntVar()]
        for p in self.vars:
            p.set(1)

        self.vulnerable_ports = ["21/tcp", "23/udp", "25/tcp", "80/tcp", "113/tcp", "137/tcp",
                                 "139/tcp", "555/tcp", "666/tcp", "1001/tcp", "1025/tcp",
                                "1026/tcp", "1028/tcp", "1243/tcp", "2000/tcp", "5000/tcp",
                                "6667/tcp", "6670/tcp", "6711/tcp", "6969/tcp", "7000/tcp",
                                "8080/tcp", "12345/tcp", "12346/tcp", "21554/tcp", "22222/tcp",
                                "27374/tcp", "29559/tcp", "31337/tcp", "31338/tcp", "31337/udp",
                                "31338/udp"]

        frame = ttk.LabelFrame(master, text='Результат аудита сетевых интерфейсов')
        conf_frame = ttk.Frame(master, width=260)

        self.result = tk.Text(frame, wrap='word', height=36)

        self.result.tag_configure('title', font=('Verdana', 12), justify='center')

        self.chb_ports = ttk.Checkbutton(conf_frame, text='Проверка открытых TCP и UDP портов',
                                        variable=self.vars[0], onvalue=1, offvalue=0)
        self.chb_sockets = ttk.Checkbutton(conf_frame, text='Проверка открытых сокетов',
                                        variable=self.vars[1], onvalue=1, offvalue=0)
        self.chb_ext_ports = ttk.Checkbutton(conf_frame, text='Анализ внешних открытых портов',
                                        variable=self.vars[2], onvalue=1, offvalue=0)
        self.chb_vulnerable_ports = ttk.Checkbutton(conf_frame, text='Проверка наиболее уязвимых портов',
                                        variable=self.vars[3], onvalue=1, offvalue=0)
        self.chb_terminals = ttk.Checkbutton(conf_frame, text='Проверка термналов доступа',
                                        variable=self.vars[3], onvalue = 1, offvalue = 0)

        self.btn_run = ttk.Button(conf_frame, text='Запуск аудита', command=self.run_audit)

        self.ytext = ttk.Scrollbar(frame, orient='vertical', command=self.result.yview)
        self.result.configure(yscroll=self.ytext.set)

        ttk.Style().configure('Vertical.TScrollbar', troughcolor='#f6f4f2', relief=tk.GROOVE)
        ttk.Style().configure('Horizontal.TScrollbar', troughcolor='#f6f4f2')

        conf_frame.pack(side=tk.LEFT, anchor='n', fill=tk.Y)
        sep = ttk.Separator(master, orient='vertical').pack(side=tk.LEFT, anchor='n', fill=tk.Y)
        frame.pack(side=tk.LEFT, anchor='n', fill=tk.BOTH, expand=1)

        self.btn_run.pack(side=tk.BOTTOM, pady=5, padx=5, anchor='s', fill=tk.X)
        self.chb_ports.pack(anchor='w', padx=5, pady=1)
        self.chb_sockets.pack(anchor='w', padx=5, pady=0)
        self.chb_ext_ports.pack(anchor='w', padx=5, pady=0)
        self.chb_vulnerable_ports.pack(anchor='w', padx=5, pady=0)
        self.chb_terminals.pack(anchor='w', padx=5, pady=0)

        self.ytext.pack(side=tk.RIGHT, anchor='n', fill=tk.Y)
        self.result.pack(side=tk.TOP, fill=tk.BOTH, anchor='nw')

    def set_pass(self, pas):
        self.password = pas

    def run_audit(self):
        self.result.delete('1.0', 'end')
        beginning = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S\n')
        self.result.insert('end', ' Начало аудита сетевых интерфейсов:    ' + str(beginning))
        self.result.update()
        funcs = [self.check_ports, self.check_sockets, self.check_ext_ports, self.check_vulnerable_ports,
                 self.check_terminals]

        for var in range(0, len(self.vars)):
            if self.vars[var].get() == 1:
                funcs[var]()
                self.result.see('end')

        ending = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S\n')
        self.result.insert('end', '\n Окончание аудита сетевых интерфейсов: ' + str(ending))
        self.result.see('end')

        write_log(self.result.get('1.0', 'end'))

    def check_ports(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Проверка открытых TCP и UDP портов'), 'title')
        self.result.update()
        tcp_status = command_seq("sudo netstat -anp --tcp | grep -s LISTEN | awk '{$2=$3=$6=\"\"; print $0}'", self.password)[0].split('\n')
        udp_status = command_seq("sudo netstat -anp --udp | grep -s LISTEN | awk '{$2=$3=$6=\"\"; print $0}'", self.password)[0].split('\n')
        if tcp_status != ['']:
            self.result.insert('end', ' Открытые TCP порты: \n')
            for row in list(filter(None, tcp_status)):
                splitted_row = list(filter(None, row.split(' ')))
                self.result.insert('end', ' {0:<4} {1:<17} {2:<17} {3:<}\n'.format(*splitted_row))
            self.result.insert('end', "Рекомендация:\n" 
                                + "Проверьте необходимость открытых TCP - портов.")
        else:
            self.result.insert('end', '{}\n'.format('Открытые TCP порты не обнаружены'))

        if udp_status != ['']:
            self.result.insert('end', ' Открытые UDP порты: \n')
            for row in list(filter(None, udp_status)):
                splitted_row = list(filter(None, row.split(' ')))
                self.result.insert('end', ' {0:<4} {1:<17} {2:<17} {3:<}\n'.format(*splitted_row))
            self.result.insert('end', "Рекомендация:\n" 
                                + "Проверьте необходимость открытых UDP - портов.")
        else:
            self.result.insert('end', '{}\n'.format('\n Открытые UDP порты не обнаружены\n'))
        return

    def check_sockets(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Проверка открытых сокетов'), 'title')
        self.result.update()
        sockets = command_seq('sudo socklist', self.password)[0].split('\n')
        if sockets != ['']:
            self.result.insert('end', ' Список открытых сокетов: \n')
            for row in sockets:
                self.result.insert('end', ' {}\n'.format(row))
            self.result.insert('end', "Рекомендация:\n" 
                                + "Проверьте необходимость открытых сокетов в системе, и, если необходимо, закройте ненужные сокеты с помощью межсетевого экрана")
        else:
            self.result.insert('end', 'Открытые сокеты не обнаружены\n')
        return

    def check_ext_ports(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск внешних открытых портов'), 'title')
        self.result.update()
        [ext_ports, err] = command_seq('sudo nmap -sT -O localhost| grep -s open', self.password)
        if err == '':
            if ext_ports != '':
                self.result.insert('end', ' Список внешних открытых портов: \n {}'.format(ext_ports))
                #self.result.insert('end', '  {}\n'.format(ext_ports))
                self.result.insert('end', "Рекомендация:\n" 
                                + "Проверьте, нужны ли определенные открытые порты в системе. Закройте ненужные порты с помощью установки для них правил межсетевого экрана.\n\n")
            else:
                self.result.insert('end', ' Открытые внешние порты не найдены\n')
        else:
            self.result.insert('end', ' Утилита nmap не установлена\n Для продолжения необходимо установить утилиту nmap\n')
        return

    def check_vulnerable_ports(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск опасных открытых портов'), 'title')
        self.result.update()
        [ext_ports, err] = command_seq('sudo nmap -sT -O localhost| grep -s open| awk \'{print $1}\'', self.password)
        if err == '':
            if ext_ports != '':
                vulnerable = False
                ext_ports = ext_ports.split('\n')
                for port in ext_ports:
                    if port in self.vulnerable_ports:
                        vulnerable = True
                        self.result.insert('end', '  Открыт опасный порт: {}\n'.format(port))
                # self.result.insert('end', '  {}\n'.format(ext_ports))
                if not vulnerable:
                    self.result.insert('end', ' Опасные порты не найдены\n')
                else: self.result.insert('end', 
                "Проверьте, нужны ли определенные открытые порты в системе. Закройте ненужные порты с помощью установки для них правил межсетевого экрана.\n\n")
            else:
                self.result.insert('end', ' Опасные порты не найдены\n')
        else:
            self.result.insert('end',
                               ' Утилита nmap не установлена\n Для продолжения необходимо установить утилиту nmap\n')

    def check_terminals(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Проверка терминалов доступа'), 'title')
        self.result.update()
        vulnerable = False
        [ext_ports, err] = command_seq('sudo last', self.password)
        if err == '':
            terminals = command_seq('sudo last | grep -s logged | awk \'{print $2,$1}\'', self.password)[0]
            root_terms = command_seq('sudo last | grep -s logged | grep -s root| awk \'{print $2}\'', self.password)[0]
            if terminals != '':
                terminals = terminals.split('\n')
                self.result.insert('end', ' Терминалы подключенные к системе:\n  tty User\n')
                for port in terminals:
                    self.result.insert('end', ' {}\n'.format(port))
                vulnerable = True
            else:
                self.result.insert('end', ' Нет подключенных терминалов\n')

            if root_terms != '':
                root_terms = root_terms.split('\n')
                self.result.insert('end', '\n  Терминалы подключенные к системе от имени root:\n  tty\n')
                for port in root_terms:
                    self.result.insert('end', ' {}\n'.format(port))
                vulnerable = True
            else:
                self.result.insert('end', ' Терминалы подключенные от имени root не обнаружены\n\n')
            
            if vulnerable: self.result.insert('end', 
            "Следите за событиями терминалов, особенно если вход на терминал произошел от имени root.\n" 
            + "Проанализируйте систему на предмет взлома с помощью спецпрограмм, если обнаруживаете, что запущенные процессы явно Вам не принадлежат.\n\n")

        else:
            self.result.insert('end',
                               ' Утилита last не установлена\n Для продолжения необходимо установить утилиту last\n')
        return

class net_Tab(Module):
    def __init__(self, master):
        super().__init__(master, False)

        self.vulnerable_ports = ["21/tcp", "23/udp", "25/tcp", "80/tcp", "113/tcp", "137/tcp",
                                 "139/tcp", "555/tcp", "666/tcp", "1001/tcp", "1025/tcp",
                                "1026/tcp", "1028/tcp", "1243/tcp", "2000/tcp", "5000/tcp",
                                "6667/tcp", "6670/tcp", "6711/tcp", "6969/tcp", "7000/tcp",
                                "8080/tcp", "12345/tcp", "12346/tcp", "21554/tcp", "22222/tcp",
                                "27374/tcp", "29559/tcp", "31337/tcp", "31338/tcp", "31337/udp",
                                "31338/udp"]

        self.functions = {
            "Открытые порты": self.check_ports,
            "Открытые сокеты": self.check_sockets,
            "Внешние порты": self.check_ext_ports,
            "Уязвимые порты": self.check_vulnerable_ports,
            "Терминалы": self.check_terminals
        }

        self.setFuncs(self.functions)
       
    def check_ports(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Проверка открытых TCP и UDP портов'), 'title')
        self.result.update()
        tcp_status = command_seq("sudo netstat -anp --tcp | grep -s LISTEN | awk '{$2=$3=$6=\"\"; print $0}'", self.password)[0].split('\n')
        udp_status = command_seq("sudo netstat -anp --udp | grep -s LISTEN | awk '{$2=$3=$6=\"\"; print $0}'", self.password)[0].split('\n')
        if tcp_status != ['']:
            self.result.insert('end', ' Открытые TCP порты: \n')
            for row in list(filter(None, tcp_status)):
                splitted_row = list(filter(None, row.split(' ')))
                self.result.insert('end', ' {0:<4} {1:<17} {2:<17} {3:<}\n'.format(*splitted_row))
            self.result.insert('end', "Рекомендация:\n" 
                                + "Проверьте необходимость открытых TCP - портов.")
        else:
            self.result.insert('end', '{}\n'.format('Открытые TCP порты не обнаружены'))

        if udp_status != ['']:
            self.result.insert('end', ' Открытые UDP порты: \n')
            for row in list(filter(None, udp_status)):
                splitted_row = list(filter(None, row.split(' ')))
                self.result.insert('end', ' {0:<4} {1:<17} {2:<17} {3:<}\n'.format(*splitted_row))
            self.result.insert('end', "Рекомендация:\n" 
                                + "Проверьте необходимость открытых UDP - портов.")
        else:
            self.result.insert('end', '{}\n'.format('\n Открытые UDP порты не обнаружены\n'))
        return

    def check_sockets(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Проверка открытых сокетов'), 'title')
        self.result.update()
        sockets = command_seq('sudo socklist', self.password)[0].split('\n')
        if sockets != ['']:
            self.result.insert('end', ' Список открытых сокетов: \n')
            for row in sockets:
                self.result.insert('end', ' {}\n'.format(row))
            self.result.insert('end', "Рекомендация:\n" 
                                + "Проверьте необходимость открытых сокетов в системе, и, если необходимо, закройте ненужные сокеты с помощью межсетевого экрана")
        else:
            self.result.insert('end', 'Открытые сокеты не обнаружены\n')
        return

    def check_ext_ports(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск внешних открытых портов'), 'title')
        self.result.update()
        [ext_ports, err] = command_seq('sudo nmap -sT -O localhost| grep -s open', self.password)
        if err == '':
            if ext_ports != '':
                self.result.insert('end', ' Список внешних открытых портов: \n {}'.format(ext_ports))
                #self.result.insert('end', '  {}\n'.format(ext_ports))
                self.result.insert('end', "Рекомендация:\n" 
                                + "Проверьте, нужны ли определенные открытые порты в системе. Закройте ненужные порты с помощью установки для них правил межсетевого экрана.\n\n")
            else:
                self.result.insert('end', ' Открытые внешние порты не найдены\n')
        else:
            self.result.insert('end', ' Утилита nmap не установлена\n Для продолжения необходимо установить утилиту nmap\n')
        return

    def check_vulnerable_ports(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск опасных открытых портов'), 'title')
        self.result.update()
        [ext_ports, err] = command_seq('sudo nmap -sT -O localhost| grep -s open| awk \'{print $1}\'', self.password)
        if err == '':
            if ext_ports != '':
                vulnerable = False
                ext_ports = ext_ports.split('\n')
                for port in ext_ports:
                    if port in self.vulnerable_ports:
                        vulnerable = True
                        self.result.insert('end', '  Открыт опасный порт: {}\n'.format(port))
                # self.result.insert('end', '  {}\n'.format(ext_ports))
                if not vulnerable:
                    self.result.insert('end', ' Опасные порты не найдены\n')
                else: self.result.insert('end', 
                "Проверьте, нужны ли определенные открытые порты в системе. Закройте ненужные порты с помощью установки для них правил межсетевого экрана.\n\n")
            else:
                self.result.insert('end', ' Опасные порты не найдены\n')
        else:
            self.result.insert('end',
                               ' Утилита nmap не установлена\n Для продолжения необходимо установить утилиту nmap\n')

    def check_terminals(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Проверка терминалов доступа'), 'title')
        self.result.update()
        vulnerable = False
        [ext_ports, err] = command_seq('sudo last', self.password)
        if err == '':
            terminals = command_seq('sudo last | grep -s logged | awk \'{print $2,$1}\'', self.password)[0]
            root_terms = command_seq('sudo last | grep -s logged | grep -s root| awk \'{print $2}\'', self.password)[0]
            if terminals != '':
                terminals = terminals.split('\n')
                self.result.insert('end', ' Терминалы подключенные к системе:\n  tty User\n')
                for port in terminals:
                    self.result.insert('end', ' {}\n'.format(port))
                vulnerable = True
            else:
                self.result.insert('end', ' Нет подключенных терминалов\n')

            if root_terms != '':
                root_terms = root_terms.split('\n')
                self.result.insert('end', '\n  Терминалы подключенные к системе от имени root:\n  tty\n')
                for port in root_terms:
                    self.result.insert('end', ' {}\n'.format(port))
                vulnerable = True
            else:
                self.result.insert('end', ' Терминалы подключенные от имени root не обнаружены\n\n')
            
            if vulnerable: self.result.insert('end', 
            "Следите за событиями терминалов, особенно если вход на терминал произошел от имени root.\n" 
            + "Проанализируйте систему на предмет взлома с помощью спецпрограмм, если обнаруживаете, что запущенные процессы явно Вам не принадлежат.\n\n")

        else:
            self.result.insert('end',
                               ' Утилита last не установлена\n Для продолжения необходимо установить утилиту last\n')
        return
