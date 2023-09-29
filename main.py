import traceback

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    import ctypes
    from ctypes import wintypes
    import win32process
    import win32api
    import sys
    import win32con
    import psutil
    from PIL import Image, ImageTk
    import win32gui

    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_ALL_ACCESS = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD

    # Yönetici kontrolü ve UAC istemi
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    if not is_admin():
        # Re-run the program with admin rights, might trigger UAC prompt
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    
    

    class ProcessListbox(tk.Listbox):
        def __init__(self, master, **kwargs):
            super().__init__(master, **kwargs)
            self.image_list = []

        def insert(self, index, string, image=None):
            if image:
                self.image_list.append(image)
                super().insert(index, string)
                self.itemconfig(index, {'image': image})
            else:
                super().insert(index, string)

    def get_icon_for_process(pid):
        try:
            if pid == 0:  # System Idle Process
                return None
            handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
            _, exe_path = win32process.GetModuleFileNameEx(handle, 0)
            icon = win32gui.ExtractIcon(0, exe_path, 0)
            if icon:
                image = Image.fromicon(icon)
                return ImageTk.PhotoImage(image)
            return None
        except:
            return None

    def update_process_list(search_term=None):
        process_listbox.delete(0, tk.END)  # Listeyi temizleyin
        processes = get_all_processes()
        if search_term:
            processes = [(name, pid, icon) for name, pid, icon in processes if search_term.lower() in name.lower()]
        for proc, pid, icon in processes:
            process_listbox.insert(tk.END, proc, image=icon)

    def search_process():
        term = search_entry.get()
        update_process_list(term)

    def hide_thread_from_debugger(thread_handle):
        THREAD_HIDE_FROM_DEBUGGER = 0x11
        result = ctypes.windll.ntdll.NtSetInformationThread(
            thread_handle,
            THREAD_HIDE_FROM_DEBUGGER,
            0,
            0
        )
        return result == 0

    def inject_dll(dll_path, process_name):
        selected_process_name = process_listbox.get(process_listbox.curselection())
        pid = get_process_pid(selected_process_name)
        if not pid:
            messagebox.showerror("Error", f"{selected_process_name} is not running!")
            return

        process_handle = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            error_code = win32api.GetLastError()
            print(f"OpenProcess failed with error code: {error_code}")
            return

        dll_len = len(dll_path)
        addr = ctypes.windll.kernel32.VirtualAllocEx(process_handle.handle, 0, dll_len, 0x3000, 0x40)
        if not addr:
            messagebox.showerror("Error", "Memory allocation failed!")
            return

        # Belleği yazılabilir yapmak için VirtualProtectEx kullanma
        old_protect = ctypes.c_uint32()
        ctypes.windll.kernel32.VirtualProtectEx(process_handle.handle, addr, dll_len, win32con.PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))

        written = ctypes.c_int(0)
        if not ctypes.windll.kernel32.WriteProcessMemory(process_handle.handle, addr, dll_path.encode('utf-8'), dll_len, ctypes.byref(written)):
            ctypes.windll.kernel32.VirtualFreeEx(process_handle.handle, addr, 0, win32con.MEM_RELEASE)
            messagebox.showerror("Error", "Failed to write process memory!")
            return

        thread_handle = ctypes.windll.kernel32.CreateRemoteThread(process_handle.handle, None, 0, ctypes.windll.kernel32.LoadLibraryA, addr, 0, None)
        if not thread_handle:
            ctypes.windll.kernel32.VirtualFreeEx(process_handle.handle, addr, 0, win32con.MEM_RELEASE)
            messagebox.showerror("Error", "Failed to inject the DLL!")
            return

        hide_thread_from_debugger(thread_handle)
        messagebox.showinfo("Success", f"{dll_path} successfully injected into {process_name}.")

    def select_dll():
        dll_path = filedialog.askopenfilename(filetypes=[("Dynamic Link Libraries", "*.dll")])
        entry_dll.delete(0, tk.END)
        entry_dll.insert(0, dll_path)

    def get_process_pid(process_name):
        for proc in win32process.EnumProcesses():
            if proc == 0:  # System Idle Process
                continue
            try:
                handle = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, proc)
                exe_name = win32process.GetModuleFileNameEx(handle, 0)
                if process_name.lower() in exe_name.lower():
                    return proc
            except Exception as e:
                if "Erişim engellendi" not in str(e):
                    print(f"Error with process {proc}: {e}")
                continue
        return None

    def get_all_processes():
        process_list = []
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            pid = proc.info['pid']
            name = proc.info['name']
            icon = get_icon_for_process(pid)
            process_list.append((name, pid, icon))
        return process_list

    root = tk.Tk()
    root.title("DLL Injector")

    frame = tk.Frame(root)
    frame.pack(pady=20, padx=20)

    # Arama özellikleri
    lbl_search = tk.Label(frame, text="Search:")
    lbl_search.grid(row=0, column=0, sticky='w')

    search_entry = tk.Entry(frame, width=50)
    search_entry.grid(row=0, column=1)

    search_button = tk.Button(frame, text="Search", command=search_process)
    search_button.grid(row=0, column=2)

    # Proseslerin listesi
    process_listbox = ProcessListbox(frame, width=50, height=10)
    process_listbox.grid(row=1, column=0, columnspan=3, pady=(10, 0))

    lbl_dll = tk.Label(frame, text="DLL Path:")
    lbl_dll.grid(row=2, column=0, pady=10, sticky='w')

    entry_dll = tk.Entry(frame, width=50)
    entry_dll.grid(row=2, column=1, pady=10)

    btn_browse = tk.Button(frame, text="Browse", command=select_dll)
    btn_browse.grid(row=2, column=2, pady=10)

    btn_inject = tk.Button(root, text="Inject", command=lambda: inject_dll(entry_dll.get(), process_listbox.get(process_listbox.curselection()[0]) if process_listbox.curselection() else None))
    btn_inject.pack(pady=20)

    update_process_list()
    root.mainloop()

except Exception as e:
    error_msg = f"An error occurred: {e}\n{traceback.format_exc()}"
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Error", error_msg)