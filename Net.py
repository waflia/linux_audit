import datetime
from commands import *

from API import Module

class Net_Tab(Module):
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
            "Терминалы": self.check_terminals,
            "Статус межсетевого\nэкрана": self.check_firewall,
            "Проверка файла\nhosts.allow": self.check_hosts_allow,
            "Проверка файла\nhosts.deny": self.check_hosts_deny,
            "Проверка настроек\nssh и sshd": self.check_ssh_sshd
        }

        self.setFuncs(self.functions)
        self.setParams(header = "сетевых интерфейсов")
    
    def check_firewall(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка статуса межсетевого экрана iptables'), 'title')
        self.result.update()
        self.vulnerable = False
        result = command_seq('sudo iptables -V', self.password)
        if result[1] == '':
            self.result.insert('end', 'Статус iptables в системе:\n{0}\n'.format(result[0]))
            res = command_seq('sudo iptables -L', self.password)
            if res[1] == '': 
                self.result.insert('end', 'Правила iptables:\n{0}\n'.format(res[0]))
            else:
                self.result.insert('end', 'Межсетевой экран настроен неправильно или не настроены правила iptables\n', 'warning')
                self.result.insert('end', "Рекомендация:\n"
		        + "Установите необходимые пакеты и настройте правила для межсетевого экрана\n\n", 'recommendations')

        else:
            self.result.insert('end', 'Межсетевой экран отключен или не установлен.\n', 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Установите необходимые пакеты и настройте правила для межсетевого экрана\n\n", 'recommendations')

    def check_hosts_allow(self):
        self.result.insert('end', '\n{}\n\n'.format('Анализ файла /etc/hosts.allow'), 'title')
        self.result.update()
        self.vulnerable = False
        result = command_seq('sudo find /etc/hosts.allow', self.password)
        if result[1] == '':
            res = command_seq("cat < /etc/hosts.allow| grep -v '#'", self.password)
            if res[0].replace('\n', '') != '': 
                self.result.insert('end', 'Правила hosts.allow:\n{0}\n'.format(res[0]))
            else:
                self.result.insert('end', 'В файле /etc/hosts.allow нет настроенных правил\n')
        else:
            self.result.insert('end', 'Файл /etc/hosts.allow не существует.\n', 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Создайте файл /etc/hosts.allow с режимом доступа 644" 
                + "и владельцем root, также довьте ненобходимые правила фильтрации в файл\n\n", 'recommendations')

    def check_hosts_deny(self):
        self.result.insert('end', '\n{}\n\n'.format('Анализ файла /etc/hosts.deny'), 'title')
        self.result.update()
        self.vulnerable = False
        result = command_seq('sudo find /etc/hosts.deny', self.password)
        if result[1] == '':
            res = command_seq("cat < /etc/hosts.deny| grep -v '#'", self.password)
            if res[0].replace('\n', '') != '': 
                self.result.insert('end', 'Правила hosts.deny:\n{0}\n'.format(res[0]))
            else:
                self.result.insert('end', 'В файле /etc/hosts.deny нет настроенных правил\n')
        else:
            self.result.insert('end', 'Файл /etc/hosts.deny не существует.\n', 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Создайте файл /etc/hosts.deny с режимом доступа 644" 
                + "и владельцем root, также довьте необходимые правила фильтрации в файл\n\n", 'recommendations')

    def check_ssh_sshd(self):
        self.result.insert('end', '\n{}\n\n'.format('Проверка сатуса сервиса ssh'), 'title')
        self.result.update()
        self.vulnerable = False
        result = command_seq('service ssh status', self.password)
        if result[1] == '':
            self.result.insert('end', 'Статус ssh в системе:\n{0}\n'.format(result[0]))
            res = command_seq("sudo cat < /etc/ssh/ssh_config| grep -v '#'")[0].split('\n')
            self.result.insert('end', 'Настройки ssh:\n')
            for row in res:
                if row != '':
                    self.result.insert('end', '\t' + row.strip() + '\n')

            res = command_seq("sudo cat < /etc/ssh/sshd_config| grep -v '#'")[0].split('\n')
            self.result.insert('end', '\nНастройки sshd:\n')
            for row in res:
                if row != '':
                    self.result.insert('end', '\t' + row.strip() + '\n')
        else:
            self.result.insert('end', 'Сервис ssh отсутствует в системе.\n', 'warning')
            self.result.insert('end', "Рекомендация:\n"
		        + "Проверьте наличие данной службы в ее конфигурационном" 
                + "файле в /etc/init.d либо в /etc/services.\n\n", 'recommendations')

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
                                + "Проверьте необходимость открытых TCP - портов.", 'recommendations')
        else:
            self.result.insert('end', '{}\n'.format('Открытые TCP порты не обнаружены'), 'clear')

        if udp_status != ['']:
            self.result.insert('end', 'Открытые UDP порты: \n')
            for row in list(filter(None, udp_status)):
                splitted_row = list(filter(None, row.split(' ')))
                self.result.insert('end', ' {0:<4} {1:<17} {2:<17} {3:<}\n'.format(*splitted_row))
            self.result.insert('end', "Рекомендация:\n" 
                                + "Проверьте необходимость открытых UDP - портов.", 'recommendations')
        else:
            self.result.insert('end', '{}\n'.format('\n Открытые UDP порты не обнаружены\n'), 'clear')
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
                + "Проверьте необходимость открытых сокетов в системе, " 
                + "и, если необходимо, закройте ненужные сокеты с помощью межсетевого экрана", 'recommendations')
        else:
            self.result.insert('end', 'Открытые сокеты не обнаружены\n', 'clear')
        return

    def check_ext_ports(self):
        self.result.insert('end', '\n{text}\n\n'.format(text='Поиск внешних открытых портов'), 'title')
        self.result.update()
        [ext_ports, err] = command_seq('sudo nmap -sT -O localhost| grep -s open', self.password)
        if err == '':
            if ext_ports != '':
                self.result.insert('end', ' Список внешних открытых портов: \n {}'.format(ext_ports))
                self.result.insert('end', "Рекомендация:\n" 
                + "Проверьте, нужны ли определенные открытые порты в системе." 
                + "Закройте ненужные порты с помощью установки для них правил межсетевого экрана.\n\n", 'recommendations')
            else:
                self.result.insert('end', ' Открытые внешние порты не найдены\n', 'clear')
        else:
            self.result.insert('end', ' Утилита nmap не установлена\n' 
            + 'Для продолжения необходимо установить утилиту nmap\n', 'recommendations')
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
                        self.result.insert('end', '  Открыт опасный порт: {}\n'.format(port), 'recommendations')
                if not vulnerable:
                    self.result.insert('end', ' Опасные порты не найдены\n', 'clear')
                else: self.result.insert('end', "Рекомендация:\n"
                + "Проверьте, нужны ли определенные открытые порты в системе." 
                + "Закройте ненужные порты с помощью установки для них правил межсетевого экрана.\n\n")
            else:
                self.result.insert('end', ' Опасные порты не найдены\n', 'clear')
        else:
            self.result.insert('end',
            ' Утилита nmap не установлена\n Для продолжения необходимо установить утилиту nmap\n', 'recommendations')

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
                self.result.insert('end', ' Нет подключенных терминалов\n', 'clear')

            if root_terms != '':
                root_terms = root_terms.split('\n')
                self.result.insert('end', '\n  Терминалы подключенные к системе от имени root:\n  tty\n')
                for port in root_terms:
                    self.result.insert('end', ' {}\n'.format(port), 'recommendations')
                vulnerable = True
            else:
                self.result.insert('end', ' Терминалы подключенные от имени root не обнаружены\n\n', 'clear')
            
            if vulnerable: self.result.insert('end', "Рекомендация:\n"
            + "Следите за событиями терминалов, особенно если вход на терминал произошел от имени root.\n" 
            + "Проанализируйте систему на предмет взлома с " 
            + "помощью спецпрограмм, если обнаруживаете, что" 
            + "запущенные процессы явно Вам не принадлежат.\n\n", 'recommendations')

        else:
            self.result.insert('end',
            ' Утилита last не установлена\n Для продолжения необходимо установить утилиту last\n', 'recommendations')
        return
