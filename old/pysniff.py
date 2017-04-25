# -*- coding: utf-8 -*-
from scapy.all import *
from Tkinter import *
import tkMessageBox
import sys

class Application:
    pkts = {}
    def __init__(self, master=None):
        self.fontePadrao = ("Arial", "10")
        
        self.pesquisaContainer = Frame(master)
        self.pesquisaContainer["padx"] = 20
        self.pesquisaContainer.pack()

        self.filtro = Entry(self.pesquisaContainer)
        self.filtro["width"] = 68
        self.filtro["font"] = self.fontePadrao
        self.filtro.pack(side=LEFT)

        self.iniciarBtn = Button(self.pesquisaContainer)
        self.iniciarBtn["text"] = "Iniciar"
        self.iniciarBtn["font"] = self.fontePadrao
        self.iniciarBtn["width"] = 12
        self.iniciarBtn["command"] = self.iniciar
        self.iniciarBtn.pack(side=LEFT)

        self.mainContainer = Frame(master)
        self.mainContainer["pady"] = 20
        self.mainContainer.pack()

        self.listbox = Listbox(self.mainContainer)
        self.listbox["width"] = 60
        self.listbox["selectmode"] = SINGLE
        self.listbox.pack(side=LEFT)

        self.mostrarBtn = Button(self.mainContainer)
        self.mostrarBtn["text"] = "Mostrar"
        self.mostrarBtn["font"] = self.fontePadrao
        self.mostrarBtn["width"] = 12
        self.mostrarBtn["command"] = self.mostrarPkt
        self.mostrarBtn.pack(side=LEFT)

    def iniciar(self):
        sniff(iface="eth0", prn=self.addInfo, count=25, filter=self.filtro.get())

    def addInfo(self, x):
        self.pkts[self.listbox.size()] = x
        self.listbox.insert(END, str(self.listbox.size() + 1) + ". " + x.sprintf("{IP:%IP.src% -> %IP.dst%}"))

    def mostrarPkt(self):
        curs = self.listbox.curselection()

        if (curs):
            curs = curs[0]
            self.pkts[curs].show()

if len(sys.argv) < 2:
    print "Use -t para texto e -g para interface gráfica (em desenvolvimento, incompleta)"
    sys.exit()

if sys.argv[1] == "-t":
    filtro = raw_input("Entre com o filtro: ")
    iface = raw_input("Entre com a interface (padrao eth0): ") or "eth0"
    count = int(raw_input("Entre com a quantidade de pacotes (deixe em branco para infinito): ")) or 0
    print(count)
    if count == 0:
        sniff(iface="eth0", prn=lambda x: x.summary(), filter=filtro)    
    else:
        sniff(iface="eth0", prn=lambda x: x.summary(), count=count, filter=filtro)

elif sys.argv[1] == "-g":
    root = Tk()
    Application(root)
    root.mainloop()
else:
    print "Use -t para texto e -g para interface gráfica (em desenvolvimento, incompleta)"
