from extraction import *
from analyse import *
import tkinter
from tkinter import *
from tkinter import filedialog
from tkinter import ttk

def openFile():
    filepath = filedialog.askopenfilename(initialdir="\\home\\jriby\\Desktop",
    title="Open File")
    file =open(filepath,'r')
    text=file.read()
    #global t
    t=text.split('0000 ')[1:]
    #Clean_file(t)
    buttons(t)
    file.close

window = Tk()
window.title("Analyseur de protocoles")
window.geometry("900x600")
menubar = Menu(window)
window.config(menu=menubar)
fileMenu= Menu(menubar,tearoff=0)
menubar.add_cascade(label="File",menu=fileMenu)
fileMenu.add_command(label="Open",command=openFile)
#fileMenu.add_command(label="Save")
fileMenu.add_separator()
fileMenu.add_command(label="Exit",command=quit)
panedwindow=ttk.Panedwindow(window, orient=HORIZONTAL)  
panedwindow.pack(fill=BOTH, expand=True)  
fram1=ttk.Frame(panedwindow,width=100,height=300, relief=SUNKEN)  
fram2=ttk.Frame(panedwindow,width=400,height=400, relief=SUNKEN)  
panedwindow.add(fram1, weight=1)  
panedwindow.add(fram2, weight=4) 

def my_func(k):
    for widgets in fram2.winfo_children():
      widgets.destroy()
    trame = Extract_Trame(k)
    tree(fram2,trame)

def buttons(t) :
    for j in t:
        bg='green'
        if "Error line" in Extract_Trame(j): 
            bg='red'
        tx='Trame '+str(1+t.index(j))
        e = Button(fram1, text=tx,command=lambda k=j :my_func(k),bg=bg) 
        e.pack(padx=2,fill=X)

window.mainloop()

