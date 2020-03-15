"""Основной модуль программы"""
#!usr/bin/python3
from tkinter import Toplevel, BOTH, LEFT, TRUE, FALSE
from tkinter import ttk
from ttkthemes import ThemedTk
from tkinter import messagebox as mb
from tkinter import filedialog as fd
from ACL import ACL_Tab
from Base import Base_Tab
from AppArmor import AppArmor_Tab
from Net import net_Tab
from Log import log_Tab
from SELinux import SELinux_Tab
#from commands import *
from subprocess import Popen, PIPE, run


root = ThemedTk(theme='radiance')
passwd = Toplevel()
tlevel_frame = ttk.Frame(passwd)
wd = 900
ht = 650
root.withdraw()
passwd.focus_set()
password = ''
corr = False

nb = ttk.Notebook(root)
base_Frame = ttk.Frame(nb)
acl_Frame = ttk.Frame(nb)
aa_Frame = ttk.Frame(nb)
sel_Frame = ttk.Frame(nb)
net_Frame = ttk.Frame(nb)
logs_Frame = ttk.Frame(nb)

nb.add(base_Frame, text='Base')
nb.add(acl_Frame, text='ACL')
nb.add(aa_Frame, text='Apparmor')
nb.add(sel_Frame, text='SELinux')
nb.add(net_Frame, text='Network')
nb.add(logs_Frame, text='Logs')

base = Base_Tab(base_Frame, path="/home")
acl = ACL_Tab(acl_Frame, path='/home')
app_armor = AppArmor_Tab(aa_Frame)
selinux = SELinux_Tab(sel_Frame)
net = net_Tab(net_Frame)
log = log_Tab(logs_Frame)

sudopas = run('sudo -S a\n', shell=True, stdout=PIPE, stderr=PIPE, input=bytes(password + '\n', 'utf-8'))
out = sudopas.stderr.decode('utf-8')
if out == '':
    out = sudopas.stdout.decode('utf-8')

if 'sudo a:' in out:
    corr = True
else:
    corr = False


def button_click(event):
    """Функция-обработчик нажатия кнопки подтверждения пароля"""
    password = pass_Entry.get()
    pass_Label.configure(text=password)
    if(correct(password)):
        passwd.destroy()
        root.deiconify()
        base.set_pass(password)
        acl.set_pass(password)
        app_armor.set_pass(password)
        selinux.set_pass(password)
        net.set_pass(password)
    else:
        pass_Label['text'] = 'Неверный пароль!'

def correct(pas):
    """Функция проверки корректности пароля"""
    sudopas = run('sudo -S a\n', shell=True, stdout=PIPE, stderr=PIPE, input=bytes(pas + '\n', 'utf-8'))
    out = sudopas.stderr.decode('utf-8')
    if out == '':
        out = sudopas.stdout.decode('utf-8')

    if 'sudo: a:' in out:
        return True
    else:
        return False

def root_quit():
    root.destroy()

def change_tab(event):
    try:
        with open('diplom/test/last.txt', 'r') as file:
            text = file.read()
            log.set_text(text)
    except FileNotFoundError:
        mb.showinfo("", "Файл test/last.txt не найден")

if not corr:
# Конфигурирование окна ввода пароля
    width = root.winfo_screenwidth()//5 + 96
    height = root.winfo_screenheight()//5
    dw = (root.winfo_screenwidth()-width)//2
    dh = (root.winfo_screenheight()-height)//2
    passwd.geometry('{}x{}+{}+{}'.format(width, height, dw, dh))
# passwd.iconbitmap(os.path.abspath("lock.ico"))
    passwd.resizable(False, False)
    passwd.title('Введите пароль суперпользователя')

# Настройка виджетов в окне ввода пароля
    pass_Label = ttk.Label(tlevel_frame)
    pass_Entry = ttk.Entry(tlevel_frame, font=16, show='⚫')
    pass_Btn = ttk.Button(tlevel_frame, text='OK', width=15)

    pass_Entry.bind('<Return>', button_click)
    pass_Btn.bind('<Button-1>', button_click)

    pass_Label.grid(row=1, column=0)
    pass_Entry.grid(row=2, column=0, padx=10, sticky='nsew')
    pass_Btn.grid(row=3, column=0, padx=10, pady=20, sticky='e')

    tlevel_frame.pack(fill=BOTH)
    tlevel_frame.grid_rowconfigure(1, minsize=height//3)
    tlevel_frame.grid_rowconfigure(2, minsize=30)
    tlevel_frame.grid_columnconfigure(0, minsize=width)
    pass_Entry.focus_set()
else:
    passwd.destroy()
    root.deiconify()
    base.set_pass(password)
    acl.set_pass(password)
    app_armor.set_pass(password)
    selinux.set_pass(password)
    net.set_pass(password)
#####################################################################
dw = (root.winfo_screenwidth() - wd) // 2
dh = (root.winfo_screenheight() - ht) // 2
root.wm_geometry('{}x{}+{}+{}'.format(wd, ht, dw, dh))

root.title('Управление безопасностью Linux')


#file = open('test/last.txt', 'w')
#file.write('')
#file.close()

nb.enable_traversal()
nb.select(base_Frame)
nb.bind('<<NotebookTabChanged>>', change_tab)

nb.pack(side=LEFT, fill=BOTH, expand=1)
root.resizable(width=TRUE, height=FALSE)

root.mainloop()

