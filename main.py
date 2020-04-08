import os
from tkinter import ttk
from tkinter import *
from ttkthemes import ThemedTk
from ModuleLoader import Loader
from subprocess import PIPE, run

root = ThemedTk(theme='radiance')
passwd = Toplevel()
tlevel_frame = ttk.Frame(passwd)
wd = 800
ht = 600
root.withdraw()
passwd.focus_set()
password = ''
loader = None
corr = False

def button_click(event):
    """Функция-обработчик нажатия кнопки подтверждения пароля"""
    password = pass_Entry.get()
    pass_Label.configure(text=password)
    if(correct(password)):
        passwd.destroy()
        root.deiconify()
        loader = Loader(root, password)
    else:
        pass_Label['text'] = 'Неверный пароль!'

def correct(pas):
    """Функция проверки корректности пароля"""
    sudopas = run('sudo -S ls\n', shell=True, stdout=PIPE, stderr=PIPE, input=bytes(pas + '\n', 'utf-8'))
    out = sudopas.stderr.decode('utf-8')
    if out == '':
        out = sudopas.stdout.decode('utf-8')
        return True
    else:
        return False

def root_quit():
    root.destroy()

def on_closing():
    if loader != None:
        loader.write_modules()
    root.destroy()

passwd.protocol("WM_DELETE_WINDOW", on_closing)

sudopas = run('sudo -S ls\n', shell=True, stdout=PIPE, stderr=PIPE, input=bytes(password + '\n', 'utf-8'))
out = sudopas.stderr.decode('utf-8')
if out == '':
    out = sudopas.stdout.decode('utf-8')
    corr = True
else:
    corr = False

if not corr:
    # Конфигурирование окна ввода пароля
    width = root.winfo_screenwidth()//5 + 96
    height = root.winfo_screenheight()//5
    dw = (root.winfo_screenwidth()-width)//2
    dh = (root.winfo_screenheight()-height)//2
    passwd.geometry('{}x{}+{}+{}'.format(width, height, dw, dh))

    passwd.resizable(False, False)
    passwd.title('Введите пароль суперпользователя')

    # Настройка виджетов в окне ввода пароля
    pass_Label = ttk.Label(tlevel_frame)
    pass_Entry = ttk.Entry(tlevel_frame, font=16)#,how='⚫')
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
    loader = Loader(root, password)
    
dw = (root.winfo_screenwidth() - wd) // 2
dh = (root.winfo_screenheight() - ht) // 2
root.wm_geometry('{}x{}+{}+{}'.format(wd, ht, dw, dh))

root.title('Управление безопасностью Linux')
root.resizable(width=TRUE, height=FALSE)
root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()

