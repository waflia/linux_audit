import os
import datetime
import tkinter as tk
import tkinter.ttk as ttk

from tree import Tree
from Log import Log_Tab
    
class Module():
    def __init__(self, master, enableTree):
        self.password = ''
        self.path = '/'
        self.header = ""
        self.funcs = []
        self.vars = []
        self.files = dict()
        self.treeEnabled = enableTree

        self.width = 72

        self.frame = ttk.LabelFrame(master, text="Результат аудита")
        self.conf_frame = ttk.Frame(master, width=260)

        #if(enableTree):
        self.tree_frame = ttk.Frame(self.conf_frame, width=260)
        self.tree = Tree(self.tree_frame, path=self.path)

        self.result = tk.Text(self.frame, wrap='word', height=36)
        self.result.tag_configure('title', font=('Verdana', 12, 'bold'), justify='center')
        self.result.tag_configure('warning', font=('Verdana', 10, 'bold'), foreground="red")
        self.result.tag_configure('recommendations', font=('Verdana', 10, 'bold'), foreground="yellow")
        self.result.tag_configure('clear', font=('Verdana', 10, 'bold'), foreground="green")

        self.btn_run = ttk.Button(self.conf_frame, text='Запуск аудита', width = 26,command=self.run_audit)

        self.ytext = ttk.Scrollbar(self.frame, orient='vertical', command=self.result.yview)
        self.result.configure(yscroll=self.ytext.set)

        ttk.Style().configure('Treeview', rowheight=30)
        ttk.Style().configure('Vertical.TScrollbar', troughcolor='#f6f4f2', relief=tk.GROOVE)
        ttk.Style().configure('Horizontal.TScrollbar', troughcolor='#f6f4f2')

        self.conf_frame.pack(side=tk.LEFT, anchor='n', fill=tk.Y)

        sep = ttk.Separator(master, orient='vertical').pack(side=tk.LEFT, anchor='n', fill=tk.Y)
        self.frame.pack(side=tk.LEFT, anchor='n', fill=tk.BOTH, expand=1)

        self.btn_run.pack(side=tk.BOTTOM, pady=0, padx=5, anchor='s', fill=tk.X)

        self.ytext.pack(side=tk.RIGHT, anchor='n', fill=tk.Y)
        self.result.pack(side=tk.TOP, fill=tk.BOTH, anchor='nw')

        self.abspath = os.path.abspath(self.path)
        self.log = None
    
    def set_pass(self, pas):
        self.password = pas
        #if(self.treeEnabled):
        self.tree.set_pass(pas)

    def set_logs(self, logs):
        self.log = logs
        
    def run_audit(self):
        self.result.delete('1.0', 'end')
        self.width = 72
        beginning = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S\n\n')
        self.result.insert('end', ' Начало аудита {}:    '.format(self.header) + str(beginning))
        self.result.update()
        
        if(self.treeEnabled):
            self.files = self.tree.file_permissions()

        for var in range(0, len(self.vars)):
            if self.vars[var].get() == 1:
                self.funcs[var]()
                self.result.see('end')

        ending = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S\n')
        self.result.insert('end', '\n Окончание аудита {}: '.format(self.header) + str(ending))
        self.result.see('end')

        self.log.write_log(self.result.get('1.0', 'end'))
    
    def setFuncs(self, functions):
        funcsCount = len(functions)
        self.vars = [tk.IntVar() for i in range(funcsCount)]
        for var in self.vars:
            var.set(1)
        i = 0
        for key in functions.keys():
            ttk.Checkbutton(self.conf_frame, text=key, 
                            variable=self.vars[i], 
                            onvalue=1, 
                            offvalue=0).pack(side=tk.BOTTOM, anchor='sw', padx=5, pady=0)
            self.funcs.append(functions[key])
            i += 1
        if(self.treeEnabled):
            self.tree_frame.pack(side=tk.BOTTOM, fill=tk.Y, anchor='w', pady=5, padx=5, expand=1)
        
    def setParams(self, header):
        self.header = header

    
