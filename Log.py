import datetime
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog as fd
from tkinter import messagebox as mb


class Log_Tab:
    _instance = None

    def __init__(self):
        return Log_Tab._instance
        
    def __init__(self, master = None, main_path = ''):
        self.main_path = main_path

        self.bar_Frame = ttk.Frame(master)
        self.text_Frame = ttk.Frame(master)

        self.save_btn = ttk.Button(self.bar_Frame, text='Сохранить', command=self.file_save)
        self.date_label = ttk.Label(self.bar_Frame)
        self.log = tk.Text(self.text_Frame, height=40)
        self.scrollbar = ttk.Scrollbar(self.text_Frame, orient='vertical', command=self.log.yview)
        self.log.configure(yscroll=self.scrollbar.set)

        self.bar_Frame.pack(side=tk.TOP, fill=tk.X)
        self.text_Frame.pack(side=tk.BOTTOM, fill=tk.BOTH)

        self.scrollbar.pack(side=tk.RIGHT, anchor='n', fill=tk.Y)
        self.date_label.pack(side=tk.LEFT, anchor='sw', padx=10, pady=5)
        self.save_btn.pack(side=tk.RIGHT, anchor='ne', padx=15, pady=5)
        self.log.pack(side=tk.BOTTOM, anchor='sw', padx=5, pady=5, fill=tk.BOTH)

        self.date = datetime.datetime.strftime(datetime.datetime.now(), "%d-%m-%y")
        self.date_label.configure(text=self.date)
        Log_Tab._instance = self

    def set_text(self, text):
        self.log.delete('1.0', 'end')
        self.log.insert('end', text)
        self.log.see('end')

    def file_save(self):
        try:
            file = open(fd.asksaveasfilename(filetypes=(("TXT files", "*.txt"), ("All files", "*.*"))), 'w')
            file.write(self.log.get('1.0', 'end'))
            file.close()
        except:
            mb.showinfo('Внимание', 'Файл не сохранен')

    def write_log(self, text):
        try:
            with open(self.main_path + '/test/logs.txt', 'a') as file_log:
                file_log.write(text)
            with open(self.main_path + '/test/last.txt', 'a') as last_log:
                last_log.write(text)
        except FileNotFoundError:
            mb.showinfo("", "Файл {} не найден".format(self.main_path + "/test/*"))