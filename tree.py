import os
import tkinter as tk
import tkinter.ttk as ttk
from commands import *


class Tree(object):
    def __init__(self, master, path):

        self.nodes = dict()
        self.password = ''
        self.selected_dirs = []
        self.files = dict()
        self.tree_files = dict()

        self.s = []

        self.tree = ttk.Treeview(master, height=10)

        self.tree.column("#0", width=260, minwidth=150, stretch=tk.NO)

        self.ysb = ttk.Scrollbar(master, orient='vertical', command=self.tree.yview)
        self.xsb = ttk.Scrollbar(master, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscroll=self.ysb.set, xscroll=self.xsb.set)

        self.tree.heading('#0', text='Выбор каталогов для аудита', anchor='w')

        ttk.Style().configure('Treeview', rowheight=30)
        ttk.Style().configure('Vertical.TScrollbar', troughcolor='#f6f4f2', relief=tk.GROOVE)
        ttk.Style().configure('Horizontal.TScrollbar', troughcolor='#f6f4f2')

        self.ysb.pack(side=tk.RIGHT, anchor='n', fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, side=tk.TOP, anchor='nw',expand=1)
        self.xsb.pack(fill=tk.X, side=tk.BOTTOM)

        self.abspath = os.path.abspath(path)

        self.insert_node('', self.abspath, self.abspath)
        self.tree_files[''] = ''
        self.tree.bind('<<TreeviewOpen>>', self.open_node)
        self.tree.bind('<<TreeviewSelect>>', self.data_update)
        self.tree.tag_configure(tagname='selected', background='#ed7442')
        self.tree.tag_configure(tagname='none', background='')
        self.tree.bind('<ButtonRelease>', self.tree_click)

    def get_file_permissions(self, path):
        if os.path.isdir(path):
           # os.chdir(path)
            file = command_seq("sudo ls -l {}".format(path.replace(' ', '\ ')), self.password)[0].split('\n')
            list_dir = []
            for f in file:
                split_f = f.split(' ')
                split_f = list(filter(None, split_f))
                if len(split_f) > 8:
                    name = split_f[8:][0]

                    for n in split_f[9:]:
                        if split_f[0][0] == 'd':
                            name = name + ' ' + n

                    self.files[path + '/' + name] = split_f
                    list_dir.append(path + '/' + name)

            for dir in list_dir:
                    self.get_file_permissions(dir)

    def file_permissions(self):
        self.files = dict()
        for dir in self.selected_dirs:
            self.get_file_permissions(self.tree_files[dir])
        return self.files

    def set_pass(self, pas):
        self.password = pas

    def insert_node(self, parent, text, abspath):
        node = self.tree.insert(parent, 'end', text=text, open=False)
        if os.path.isdir(abspath):
            self.nodes[node] = abspath
            self.tree.insert(node, 'end')
        self.tree_files[node] = abspath

    def open_node(self, event):
        node = self.tree.focus()
        self.abspath = self.nodes.pop(node, None)
        if self.abspath:
            pt = self.abspath
            self.s = command_seq('ls -l {}'.format(pt.replace(' ', '\ ')), self.password)[0].split('\n')
            self.tree.delete(self.tree.get_children(node))
            for p in os.listdir(self.abspath):
                if p[0] != '.':
                    self.insert_node(node, p, os.path.join(self.abspath, p))

    def tree_click(self, event):
        item = self.tree.identify_row(event.y)
        if item not in self.selected_dirs:
            self.tree.item(item, tag='selected')
            self.selected_dirs.append(item)
            parent = self.tree.parent(item)
            self.tree.item(parent, tag='none')
            if parent in self.selected_dirs:
                self.selected_dirs.remove(parent)
            for ch_item in self.tree.get_children(item):
                self.tree.item(ch_item, tag='none')
                if ch_item in self.selected_dirs:
                    self.selected_dirs.remove(ch_item)
        else:
            self.tree.item(item, tag='none')
            for ch_item in self.tree.get_children(item):
                self.tree.item(ch_item, tag='none')
                if ch_item in self.selected_dirs:
                    self.selected_dirs.remove(ch_item)
            self.selected_dirs.remove(item)

    def data_update(self, event):
    # Изменение размера горизонтального ползунка
        col_len = len(self.tree_files[self.tree.parent(self.tree.selection()[0])])*7 + len(self.tree.item(self.tree.selection()[0])['text'])*7

        if col_len > self.tree.column('#0', 'width'):
            self.tree.column('#0', width=col_len)
