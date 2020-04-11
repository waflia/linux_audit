import os
import json
from tkinter import ttk
import tkinter as tk

from other.scrollableFrame import VerticalScrolledFrame

class main_Tab:
           
    def __init__(self, master, main_path = ''):
        self.main_path = main_path
        self.master = master

        self.fio = ''
        self.org = ''

        #Профили аудита
        self.profiles = {}
        self.current_profile_options = {}

        #Левый фрейм включает данные об аудиторе и о существующих профилях
        leftFrame = ttk.Frame(master)
        self.auditor_Frame = ttk.LabelFrame(leftFrame, text='Данные аудитора')
        self.profiles_Frame = VerticalScrolledFrame(leftFrame, text='Профили аудита')

        #Правый фрейм включает редактор текущего профиля и кнопку запуска аудита
        rightFrame = ttk.Frame(master)
        self.current_Frame = ttk.LabelFrame(rightFrame, text='Текущий профиль')
        #self.profiles_Label = ttk.Label(self.current_Frame, text='Текущий профиль')
        #self.profiles_Label.pack(side=tk.TOP, anchor='nw', expand=1, fill=tk.BOTH)
        self.btn_Frame = ttk.Frame(rightFrame)

        #Область данных об аудиторе
        fio_Label = ttk.Label(self.auditor_Frame, text='ФИО')
        self.fio_Entry = ttk.Entry(self.auditor_Frame, font=16, width = 30)
        self.fio_Label = ttk.Label(self.auditor_Frame, font=16, width = 30)
        org_Label = ttk.Label(self.auditor_Frame, text='Организация')
        self.org_Entry = ttk.Entry(self.auditor_Frame, font=16, width = 30)
        self.org_Label = ttk.Label(self.auditor_Frame, font=16, width = 30)
        self.fio_OK_btn = ttk.Button(self.auditor_Frame, text='OK', width=5, command=self.accept_auditor)

        fio_Label.grid(row=1, column=0, sticky='new', padx=10)
        self.fio_Entry.grid(row=2, column=0, sticky='nsew', padx=10)
        org_Label.grid(row=3, column=0, sticky='new', padx=10)
        self.org_Entry.grid(row=4, column=0, sticky='nsew', padx=10)
        self.fio_OK_btn.grid(row=5, column=0, sticky='se', padx=10)

        ttk.Style().configure('Vertical.TScrollbar', troughcolor='#f6f4f2', relief=tk.GROOVE)

        self.save_audit_btn = ttk.Button(self.btn_Frame, text='Сохранить профиль', command=self.save_btn_click)
        self.run_audit_btn = ttk.Button(self.btn_Frame, text='Запустить аудит', command=self.run_audit)

        #Размещения на фреймах
        leftFrame.pack(side=tk.LEFT, anchor='nw', fill=tk.Y)
        rightFrame.pack(side=tk.LEFT, anchor='nw', expand=1, fill=tk.BOTH)

        self.auditor_Frame.pack(side=tk.TOP, anchor='nw', padx=5, pady = 5, fill=tk.X)
        self.profiles_Frame.pack(side=tk.TOP, anchor='sw', padx=5, pady = 10, fill=tk.BOTH, expand=1)

        self.current_Frame.pack(side=tk.TOP, anchor='nw', padx=5, pady=5, fill=tk.BOTH, expand=1)
        self.btn_Frame.pack(side=tk.TOP, anchor='nw', fill=tk.X)
        
        self.save_audit_btn.pack(side=tk.LEFT, anchor='sw', padx=5, pady=5)
        self.run_audit_btn.pack(side=tk.LEFT, anchor='se', padx=5, pady=5, fill=tk.X, expand=1)
        
        self.auditor_Frame.grid_rowconfigure(2, minsize=30)
        self.loadProfiles()        
        
    def run_audit(self):
        pass

    def accept_auditor(self):
        if  self.fio_OK_btn.cget('text') == 'OK':
            self.fio = self.fio_Entry.get()
            self.org = self.org_Entry.get()

            self.fio_OK_btn.configure(text='Изменить', width=10)

            self.fio_Entry.grid_remove()
            self.org_Entry.grid_remove()

            self.fio_Label.configure(text=self.fio)
            self.org_Label.configure(text=self.org)
            self.fio_Label.grid(row=2, column=0, sticky='nsew', padx=10)
            self.org_Label.grid(row=4, column=0, sticky='nsew', padx=10)
        else:
            self.fio_OK_btn.configure(text='OK', width=5)
            self.fio_Entry.grid()
            self.org_Entry.grid()

            self.fio_Label.grid_remove()
            self.org_Label.grid_remove()

    def loadProfiles(self):
        self.profiles_Frame.pack(side=tk.TOP, anchor='sw', padx=5, pady = 10, fill=tk.BOTH, expand=1)
        try:
            with open(self.main_path + '/profiles.json') as file:
                self.profiles = json.load(file)
        except:
            with open(self.main_path + '/profiles.json', 'w') as file:
                json.dump(self.profiles, file)
        
        prof_count = len(self.profiles)
        self.var = tk.IntVar()
        for i in range(prof_count):
            tk.Radiobutton(self.profiles_Frame.interior, variable=self.var, value=i,
                             indicator=0,height=3, text=list(self.profiles.keys())[i], 
                             command=self.changeCurrentProfile).pack(side=tk.TOP, anchor='nw', fill=tk.X, padx=5, pady=2)
    
    def dumpProfiles(self):
        with open(self.main_path + '/profiles.json', 'w') as file:
            json.dump(self.profiles, file)

    def changeCurrentProfile(self):
        self.profiles_Label.configure(text=self.var.get())

    def save_btn_click(self):
        self.saveDialog = tk.Toplevel()
        save_frame = ttk.Frame(self.saveDialog)
        self.saveDialog.focus_set()

        width = self.master.winfo_screenwidth()//5 + 96
        height = self.master.winfo_screenheight()//5
        dw = (self.master.winfo_screenwidth()-width)//2
        dh = (self.master.winfo_screenheight()-height)//2
        self.saveDialog.geometry('{}x{}+{}+{}'.format(width, height, dw, dh))

        self.saveDialog.resizable(False, False)
        self.saveDialog.title('Сохранение профиля')

        # Настройка виджетов в окне ввода пароля
        save_Label = ttk.Label(save_frame, text='Названия профиля')
        self.save_Entry = ttk.Entry(save_frame, font=16)
        save_Btn = ttk.Button(save_frame, text='Сохранить', width=15)

        self.save_Entry.bind('<Return>', self.save_click)
        save_Btn.bind('<Button-1>', self.save_click)

        save_Label.grid(row=1, column=0)
        self.save_Entry.grid(row=2, column=0, padx=10, sticky='nsew')
        save_Btn.grid(row=3, column=0, padx=10, pady=20, sticky='e')

        save_frame.pack(fill=tk.BOTH)
        save_frame.grid_rowconfigure(1, minsize=height//3)
        save_frame.grid_rowconfigure(2, minsize=30)
        save_frame.grid_columnconfigure(0, minsize=width)
        self.save_Entry.focus_set()

    def save_click(self, event):
        """Функция-обработчик нажатия кнопки """
        profile_name = self.save_Entry.get()
        self.profiles[profile_name] = self.current_profile_options
        self.dumpProfiles()
        self.loadProfiles()
        self.saveDialog.destroy()
        
        
        