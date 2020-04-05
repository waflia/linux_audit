import json
import importlib
import inspect
import os
from tkinter import ttk
from tkinter import LEFT, BOTH, messagebox as mb, filedialog as fd

from Log import Log_Tab
from API import Module

class Loader():
    def __init__(self, root_Frame, password):
        self.root = root_Frame
        self.path = os.path.dirname(inspect.getfile(inspect.currentframe()))
        self.nb = ttk.Notebook(root_Frame)
        self.password = password
        logs_Frame = ttk.Frame(self.nb)
        addNewModule_Frame = ttk.Frame(self.nb)
        self.log = Log_Tab(logs_Frame, self.path)

        self.modules = {}
        self.read_modules()
        self.importModules()

        self.nb.add(logs_Frame, text='Logs')
        self.nb.add(addNewModule_Frame, text='+')

        self.nb.enable_traversal()
        self.nb.bind('<<NotebookTabChanged>>', self.change_tab)
        self.nb.pack(side=LEFT, fill=BOTH, expand=1)
        self.nb.select(self.nb.index(0))
        
    def read_modules(self):
        try:
            with open(self.path + '/modules.json') as file:
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
            with open(self.path + '/modules.json', 'w') as file:
                json.dump(self.modules, file)
        except(FileNotFoundError):
            pass
    
    def addModule(self, tab_name, module_name, spec=None):
        self.modules[tab_name] = module_name
        self.write_modules()
        module = None
        if spec != None:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        else:
            module = importlib.import_module(module_name)
        tab = None
        for x in dir(module):
            obj = getattr(module, x)
            if inspect.isclass(obj) and issubclass(obj, Module):#"_Tab" in obj.__name__
                tab = obj
                break
        if tab != None:
            tabFrame = ttk.Frame(self.nb)
            self.nb.insert(self.nb.index('end') - 2, tabFrame, text = tab_name)
            self.nb.select(self.nb.index('end') - 3)
            newTab = tab(tabFrame)
            newTab.set_pass(self.password)
            newTab.set_logs(self.log)

    def delModule(self, Tab_Name, index = None):
        self.modules.pop(Tab_Name)
        self.write_modules()
        self.nb.forget('current')
    
    def importModules(self):
        for tab_name, module_name in self.modules.items():
            module = None
            spec = importlib.util.spec_from_file_location(tab_name, module_name)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
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
                newTab.set_logs(self.log)
            else:
                self.modules[tab_name] = ''

    def change_tab(self, event):
        try:
            with open(self.path + '/test/last.txt', 'r') as file:
                text = file.read()
                self.log.set_text(text)
        except FileNotFoundError:
            mb.showinfo("", "Файл last.txt не найден")
        
        if self.nb.tab(self.nb.select(), 'text') == '+':
            filenames = fd.askopenfilenames(filetypes=(("Python files", "*.py"), ("All files", "*.*")))
            for filename in filenames:
                module_name = filename.split('/')[-1].split('.')[0]
                spec = importlib.util.spec_from_file_location(module_name, filename)
                self.addModule(module_name, filename, spec)

        