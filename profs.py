import os
import json
import copy
from tkinter import ttk
import tkinter as tk
from ttkwidgets import CheckboxTreeview

from other.scrollableFrame import VerticalScrolledFrame

class main_Tab:
           
    def __init__(self, master, main_path = ''):
        self.main_path = main_path
        self.master = master
        self.modules_config = {} #{module_name : }
        self.modules = {}

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

        self.profileView = CheckboxTreeview(self.current_Frame)
        self.save_audit_btn = ttk.Button(self.btn_Frame, text='Сохранить профиль', command=self.save_btn_click)
        self.run_audit_btn = ttk.Button(self.btn_Frame, text='Запустить аудит', command=self.run_audit)

        self.ysb = ttk.Scrollbar(self.current_Frame, orient='vertical', command=self.profileView.yview)
        self.profileView.configure(yscroll=self.ysb.set)
        ttk.Style().configure('Vertical.TScrollbar', troughcolor='#f6f4f2', relief=tk.GROOVE)
        ttk.Style().configure('Treeview', background="#ffffff")
        ttk.Style().configure('Frame', background="#f6f4f2")

        #Размещения на фреймах
        leftFrame.pack(side=tk.LEFT, anchor='nw', fill=tk.Y)
        rightFrame.pack(side=tk.LEFT, anchor='nw', expand=1, fill=tk.BOTH)

        self.auditor_Frame.pack(side=tk.TOP, anchor='nw', padx=5, pady = 5, fill=tk.X)
        self.profiles_Frame.pack(side=tk.TOP, anchor='sw', padx=5, pady = 10, fill=tk.BOTH, expand=1)

        self.current_Frame.pack(side=tk.TOP, anchor='nw', padx=5, pady=5, fill=tk.BOTH, expand=1)
        self.btn_Frame.pack(side=tk.TOP, anchor='nw', fill=tk.X)
        
        self.ysb.pack(side=tk.RIGHT, anchor='n', fill=tk.Y)
        self.profileView.pack(side=tk.TOP, anchor='nw', fill=tk.BOTH, expand=1)
        self.save_audit_btn.pack(side=tk.LEFT, anchor='sw', padx=5, pady=5)
        self.run_audit_btn.pack(side=tk.LEFT, anchor='se', padx=5, pady=5, fill=tk.X, expand=1)
        
        self.auditor_Frame.grid_rowconfigure(2, minsize=30)
        self.loadProfiles() 
        self.profileView.bind("<Button-1>", self.check_uncheck_item, True)
        
    def run_audit(self):
        for tab_name, tab in self.modules.items():
            tab.run_audit()

    def sync_vars(self):
        for tab_name, tab in self.modules.items():
            if type(self.current_profile_options[tab_name][1]) != type({}): 
                i = 0
                for var in tab.vars:
                    var.set(self.current_profile_options[tab_name][1][i])
                    i+=1
            else:
                i = len(tab.vars) - 1
                for second_tab_name, second_tab in self.current_profile_options[tab_name][1].items():
                    for j in range(len(second_tab[1]) - 1, -1, -1):
                        tab.vars[i].set(second_tab[1][j])
                        i-=1
                    
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
        for child in self.profiles_Frame.interior.winfo_children():
            child.destroy()
        #self.profiles_Frame.pack(side=tk.TOP, anchor='sw', padx=5, pady = 10, fill=tk.BOTH, expand=1)
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
                             indicator=0,height=3, text=list(self.profiles.keys())[i], selectcolor="#f19572", activebackground="#f19572",
                             command=self.changeCurrentProfile).pack(side=tk.TOP, anchor='nw', fill=tk.X, padx=5, pady=2)
    
    def dumpProfiles(self):
        with open(self.main_path + '/profiles.json', 'w') as file:
            json.dump(self.profiles, file)

    def changeCurrentProfile(self):
        currentProfileName = list(self.profiles.keys())[self.var.get()]
        self.current_profile_options=copy.deepcopy(self.profiles[currentProfileName])
        self.profileView.heading('#0', text=list(self.profiles.keys())[self.var.get()], anchor='w')
        self.initTree()
        self.sync_vars()
        #self.profiles_Label.configure(text=self.var.get())

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
        self.initTree()

    def initTree(self):
        if self.current_profile_options == {}:
            self.current_profile_options=dict(self.profiles["Профиль по умолчанию"])
        
        for (key, value) in self.current_profile_options.items():
            if self.modules_config.__contains__(key):
                if not self.profileView.exists(key):
                    self.profileView.insert("", "end", key, text=key)

                self.profileView.change_state(key, value[0])
                value = value[1]

                if type(value) == type("1"):
                    i = 0
                    for func_key in self.modules_config[key][0].keys():
                        func_key = func_key.replace('\n', ' ')

                        if not self.profileView.exists(key + func_key + "_" + str(i)):
                            self.profileView.insert(key, "end", key + func_key + "_" + str(i), text=func_key)

                        if value[i] == '0':
                            self.profileView.change_state(key + func_key + "_" + str(i), 'unchecked')
                        if value[i] == '1':
                            self.profileView.change_state(key + func_key + "_" + str(i), 'checked')
                        i+=1
                else:
                    j = 0
                    for (second_key, second_value) in dict(value).items():

                        if not self.profileView.exists(second_key):
                            self.profileView.insert(key, "end", second_key, text=second_key)
                        
                        self.profileView.change_state(second_key, second_value[0])
                        second_value = second_value[1]

                        if type(value[second_key][1]) == type("1"):
                            i = 0
                            for func_key in self.modules_config[key][0][j].keys():
                                func_key = func_key.replace('\n', ' ')

                                if not self.profileView.exists(second_key + func_key + "_" + str(i)):
                                    self.profileView.insert(second_key, "end", second_key + func_key + "_" + str(i), text=func_key)
                                
                                if value[second_key][1][i] == '0':
                                    self.profileView.change_state(second_key + func_key + "_" + str(i), 'unchecked')
                                if value[second_key][1][i] == '1':
                                    self.profileView.change_state(second_key + func_key + "_" + str(i), 'checked')
                                i+=1
                        j+=1
                
    def check_uncheck_item(self, event):
        x, y, widget = event.x, event.y, event.widget
        elem = widget.identify("element", x, y)
        if "image" in elem:
            # a box was clicked
            item = self.profileView.identify_row(y)
            children = self.profileView.get_children(item)
            parents = []
            parent = widget.parent(item)
            i = 0
            while parent != '':
                parents.append(parent)
                parent = widget.parent(parent)
            if parents and children == ():
                tag = self.profileView.item(parents[-1], "tags")
                self.current_profile_options[parents[-1]][0] = tag[0]
                if len(parents) == 2:
                    tag = self.profileView.item(parents[0], "tags")
                    self.current_profile_options[parents[-1]][1][parents[-2]][0] = tag[0]
                    tag = self.profileView.item(item, "tags")

                    i = int(item.split('_')[1])
                    varL = self.current_profile_options[parents[-1]][1][parents[-2]][1][0:i]
                    varR = self.current_profile_options[parents[-1]][1][parents[-2]][1][i + 1:]

                    if "checked" in tag:
                        self.current_profile_options[parents[-1]][1][parents[-2]][1] = varL + '1' + varR
                    else:
                        self.current_profile_options[parents[-1]][1][parents[-2]][1] = varL + '0' + varR
                else:
                    tag = self.profileView.item(item, "tags")

                    i = int(item.split('_')[1])
                    varL = self.current_profile_options[parents[-1]][1][0:i]
                    varR = self.current_profile_options[parents[-1]][1][i + 1:]

                    if "checked" in tag:
                        self.current_profile_options[parents[-1]][1] = varL + '1' + varR
                    else:
                        self.current_profile_options[parents[-1]][1] = varL + '0' + varR
            else:
                tag = self.profileView.item(item, "tags")
                self.current_profile_options[item][0] = tag[0]
                profile_1 = ''
                for child in self.profileView.get_children(item):
                    children = self.profileView.get_children(child)
                    if children != ():
                        tag = self.profileView.item(child, "tags")
                        self.current_profile_options[item][1][child][0] = tag[0]
                        profile = ''
                        for s_child in self.profileView.get_children(child):
                            tag = self.profileView.item(s_child, "tags")
                            if 'checked' in tag:
                                profile += '1'
                            else:
                                profile += '0'
                        self.current_profile_options[item][1][child][1] = profile
                    else:
                        tag = self.profileView.item(child, "tags")
                        if 'checked' in tag:
                            profile_1 += '1'
                        else:
                            profile_1 += '0'
                        self.current_profile_options[item][1] = profile_1  
        self.sync_vars()