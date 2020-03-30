import json
import importlib
import inspect
from tkinter import ttk
from tkinter import LEFT, BOTH, messagebox as mb, filedialog as fd

from Log import Log_Tab
from API import Module

class Loader():
    def __init__(self, root_Frame, password):
        self.root = root_Frame
        self.nb = ttk.Notebook(root_Frame)
        self.password = password
        self.modules = {}
        self.read_modules()
        self.importModules()

        logs_Frame = ttk.Frame(self.nb)
        addNewModule_Frame = ttk.Frame(self.nb)
        self.nb.add(logs_Frame, text='Logs')
        self.nb.add(addNewModule_Frame, text='+')
        self.log = Log_Tab(logs_Frame)

        self.nb.enable_traversal()
        self.nb.bind('<<NotebookTabChanged>>', self.change_tab)
        self.nb.pack(side=LEFT, fill=BOTH, expand=1)

    def read_modules(self):
        try:
            with open('modules.json') as file:
                self.modules = json.load(file)
        except:
            file.close()
            self.write_modules()
    
    def write_modules(self):
        keys = list(self.modules.keys())
        for key in keys:
            if self.modules[key] == '':
                self.modules.pop(key)

        try:
            with open('modules.json', 'w') as file:
                json.dump(self.modules, file)
        except(FileNotFoundError):
            pass
    
    def addModule(self, tab_name, module_name):
        self.modules[tab_name] = module_name
        self.write_modules()
        module = importlib.import_module(module_name)
        tab = None
        for x in dir(module):
            obj = getattr(module, x)
            if inspect.isclass(obj) and "_Tab" in obj.__name__ and issubclass(obj, Module):
                tab = obj
                break
        if tab != None:
            tabFrame = ttk.Frame(self.nb)
            self.nb.add(tabFrame, text = tab_name)
            newTab = tab(tabFrame)
            newTab.set_pass(self.password)

    def delModule(self, Tab_Name):
        self.modules.pop(Tab_Name)
        self.write_modules()
    
    def importModules(self):
        for tab_name, module_name in self.modules.items():
            module = importlib.import_module(module_name)
            tab = None
            for x in dir(module):
                obj = getattr(module, x)
                if inspect.isclass(obj) and "_Tab" in obj.__name__ and issubclass(obj, Module):
                    tab = obj
                    break
            if tab != None: 
                tabFrame = ttk.Frame(self.nb)
                self.nb.add(tabFrame, text = tab_name)
                newTab = tab(tabFrame)
                newTab.set_pass(self.password)
            else:
                self.modules[tab_name] = ''

    def change_tab(self, event):
        try:
            with open('./test/last.txt', 'r') as file:
                text = file.read()
                self.log.set_text(text)
        except FileNotFoundError:
            mb.showinfo("", "Файл /last.txt не найден")
        
        if self.nb.tab(self.nb.select(), 'text') == '+':
            filenames = fd.askopenfilenames(filetypes=(("Python files", "*.py"), ("All files", "*.*")))
            for filename in filenames:
                module_name = filename.split('/')[-1].split('.')[0]
                self.addModule(module_name, module_name)
            # module = importlib.import_module(module_name)
            # tab = None
            # for x in dir(module):
            #     obj = getattr(module, x)
            #     if inspect.isclass(obj) and "_Tab" in obj.__name__:
            #         tab = obj
            #         break
            # new_frame = ttk.Frame(nb)
            # nb.insert(nb.index('end') - 1, new_frame, text = module_name)
            # new_tab = tab(new_frame)
            # new_tab.set_pass(password)

        