import os
import platform
import base64
import secrets
import string
import time
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sv_ttk
import json

APP_NAME = "PasswordStore"
HOME = Path.home()
DEFAULT_WIDTH = 700
DEFAULT_HEIGHT = 650
DEFAULT_EXTENSION = ".mcdal"
SALT_NAME = "salt.bin"
INDEX_NAME = "index.json"

def _get_default_storage_path() -> str:
    system = platform.system()
    storage_candidates = _get_removable_drives()

    for candidate_base in storage_candidates:
        try:
            path = candidate_base / APP_NAME
            path.mkdir(parents=True, exist_ok=True)
            return str(path)
        except (PermissionError, OSError):
            continue

    fallback_path = HOME / f".{APP_NAME.lower()}"
    fallback_path.mkdir(parents=True, exist_ok=True)
    return str(fallback_path)

def _get_removable_drives() -> list[Path]:
    system = platform.system()
    drives = []
    if system == "Linux" or system == "Darwin":
        for mount_point in ('/media', '/run/media', '/mnt'):
            if os.path.isdir(mount_point):
                for entry in os.listdir(mount_point):
                    path_lvl1 = Path(mount_point) / entry
                    if path_lvl1.is_dir() and os.access(path_lvl1, os.W_OK):
                        drives.append(path_lvl1)
                        for sub_entry in os.listdir(path_lvl1):
                            path_lvl2 = path_lvl1 / sub_entry
                            if path_lvl2.is_dir() and os.access(path_lvl2, os.W_OK):
                                drives.append(path_lvl2)
    elif system == "Windows":
        for drive in (f"{chr(c)}:" for c in range(ord('D'), ord('Z') + 1)):
            if os.path.isdir(drive):
                drives.append(Path(drive))
    return drives

DEFAULT_STORE = _get_default_storage_path()

def ensure_storage(path: str):
    os.makedirs(path, exist_ok=True)

CATEGORIES = {
    "lower": list(string.ascii_lowercase),
    "upper": list(string.ascii_uppercase),
    "digits": list(string.digits),
    "symbols": list("!@#$%&*()-_=+[]{};:,.<>?/")
}

def generate_password(length: int = 12) -> str:
    rng = secrets.SystemRandom()
    cats = list(CATEGORIES.keys())
    password_chars = []

    if length < 4:
        return ''.join(rng.choice(string.ascii_letters + string.digits + "!@#$%&*") for _ in range(length))

    for cat in cats:
        password_chars.append(rng.choice(CATEGORIES[cat]))

    remaining = length - len(password_chars)
    prev_cat = None
    for _ in range(remaining):
        choices = cats.copy()
        if prev_cat and len(choices) > 1:
            choices.remove(prev_cat)
        cat = rng.choice(choices)
        password_chars.append(rng.choice(CATEGORIES[cat]))
        prev_cat = cat

    rng.shuffle(password_chars)
    return ''.join(password_chars)

class Vault:
    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        ensure_storage(self.storage_path)
        self.index_path = os.path.join(self.storage_path, INDEX_NAME)

        if os.path.exists(self.index_path):
            try:
                with open(self.index_path, 'r', encoding='utf-8') as f:
                    self.index = json.load(f)
            except Exception:
                self.index = {}
        else:
            self.index = {}

        self._reconcile_files()

    def _reconcile_files(self):
        try:
            files_in_dir = {f for f in os.listdir(self.storage_path) if f.endswith(DEFAULT_EXTENSION)}
        except FileNotFoundError:
            files_in_dir = set()

        indexed_files = {v['file'] for v in self.index.values()}
        missing_from_index = files_in_dir - indexed_files
        if missing_from_index:
            for filename in missing_from_index:
                safe_name = filename.replace(DEFAULT_EXTENSION, '')
                display_name = safe_name
                ts = 0
                try:
                    with open(os.path.join(self.storage_path, filename), 'r', encoding='utf-8') as f:
                        payload = json.load(f)
                        display_name = payload.get('name', safe_name)
                except (json.JSONDecodeError, OSError, KeyError):
                    pass
                self.index[safe_name] = {'file': filename, 'display_name': display_name, 'ts': ts}
            self._save_index()

    def _save_index(self):
        with open(self.index_path, 'w', encoding='utf-8') as f:
            json.dump(self.index, f, indent=4)

    def sanitize_name(self, name: str) -> str:
        keep = "-_ .()[]"
        safe = ''.join(c for c in name if c.isalnum() or c in keep).strip()
        if not safe:
            safe = base64.urlsafe_b64encode(name.encode()).decode()[:12]
        return safe

    def save_password(self, name: str, password: str, ext: str = DEFAULT_EXTENSION):
        safe = self.sanitize_name(name)
        filename = safe + ext
        path = os.path.join(self.storage_path, filename)
        payload = {
            'name': name,
            'password': password,
            'created_at': datetime.utcnow().isoformat() + 'Z'
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=4)

        self.index[safe] = {
            'file': filename,
            'display_name': name,
            'ts': time.time()
        }
        self._save_index()

    def list_items(self):
        return [(k, v['display_name']) for k, v in sorted(self.index.items(), key=lambda x: x[1]['ts'], reverse=True)]

    def read_password(self, safe_name: str):
        if safe_name not in self.index:
            return None
        filename = self.index[safe_name]['file']
        path = os.path.join(self.storage_path, filename)
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                payload = json.load(f)
            return payload
        except (json.JSONDecodeError, OSError):
            return None

    def change_storage(self, new_path: str):
        ensure_storage(new_path)
        if os.path.exists(self.index_path):
            with open(self.index_path, 'r', encoding='utf-8') as src, open(os.path.join(new_path, INDEX_NAME), 'w', encoding='utf-8') as dst:
                dst.write(src.read())
        self.storage_path = new_path
        self.index_path = os.path.join(self.storage_path, INDEX_NAME)

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Vault")
        self.root.geometry(f"{DEFAULT_WIDTH}x{DEFAULT_HEIGHT}")
        self.root.resizable(False, False)

        sv_ttk.set_theme("dark")
        if platform.system() == "Windows":
            self.root.wm_attributes("-transparentcolor", "#2b2b2b")

        self.storage_path = DEFAULT_STORE
        self.extension = DEFAULT_EXTENSION
        self.vault = None
        self.dark_mode = tk.BooleanVar(value=True)

        # Main container
        self.main_container = ttk.Frame(self.root, padding=10)
        self.main_container.pack(fill='both', expand=True)

        # Notebook for tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill='both', expand=True)

        self.tab_passwords = ttk.Frame(self.notebook)
        self.tab_generate = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_passwords, text='Vault')
        self.notebook.add(self.tab_generate, text='Generate Password')
        self.notebook.add(self.tab_settings, text='Settings')

        self.build_passwords_tab()
        self.build_generate_tab()
        self.build_settings_tab()
        self.initialize_vault()

        self.root.bind('<F5>', lambda e: self.refresh_list())

    def initialize_vault(self):
        ensure_storage(self.storage_path)
        try:
            self.vault = Vault(self.storage_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize vault: {e}")
            self.root.destroy()
            return
        self.refresh_list()

    def build_passwords_tab(self):
        frm = self.tab_passwords
        frm.columnconfigure(0, weight=1)
        frm.rowconfigure(1, weight=1)

        # Search bar
        search_frame = ttk.Frame(frm)
        search_frame.pack(fill='x', pady=(0, 10))
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_list)
        ttk.Entry(search_frame, textvariable=self.search_var, width=30, font=('Arial', 10)).pack(side='left', padx=(0, 5))
        ttk.Label(search_frame, text="Search:", font=('Arial', 10)).pack(side='left')

        # Main content
        main_frame = ttk.Frame(frm)
        main_frame.pack(fill='both', expand=True)
        main_frame.columnconfigure(1, weight=1)

        # Left: Password list
        left_frame = ttk.Frame(main_frame)
        left_frame.grid(row=0, column=0, sticky='nsw', padx=(0, 10))
        ttk.Label(left_frame, text='Saved Passwords:', font=('Arial', 12, 'bold')).pack(anchor='w', pady=(0, 5))

        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill='both', expand=True)
        self.listbox = tk.Listbox(list_frame, width=30, height=22, font=('Arial', 10))
        self.listbox.pack(side='left', fill='both', expand=True)
        self.listbox.bind('<<ListboxSelect>>', lambda e: self.on_select())

        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox.config(yscrollcommand=scrollbar.set)

        # Right: Password details
        right_frame = ttk.Frame(main_frame)
        right_frame.grid(row=0, column=1, sticky='nsew', padx=10)
        ttk.Label(right_frame, text='Password Details:', font=('Arial', 12, 'bold')).pack(anchor='w', pady=(0, 10))
        
        self.detail_name = ttk.Label(right_frame, text='Name: —', font=('Arial', 10))
        self.detail_name.pack(anchor='w', pady=(0, 5))
        self.detail_created = ttk.Label(right_frame, text='Created: —', font=('Arial', 10))
        self.detail_created.pack(anchor='w', pady=(0, 15))

        pwd_frame = ttk.Frame(right_frame)
        pwd_frame.pack(fill='x', pady=(0, 10))
        self.password_var = tk.StringVar(value='')
        self.password_entry = ttk.Entry(pwd_frame, textvariable=self.password_var, show='*', width=30, font=('Arial', 10))
        self.password_entry.pack(side='left', fill='x', expand=True)
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(pwd_frame, text='Show', variable=self.show_var, command=self.toggle_show).pack(side='left', padx=10)

        btn_frame = ttk.Frame(right_frame)
        btn_frame.pack(fill='x', pady=10)
        ttk.Button(btn_frame, text='Copy to Clipboard', command=self.copy_password, style='Accent.TButton').pack(side='left')
        ttk.Button(btn_frame, text='Delete', command=self.delete_selected, style='TButton').pack(side='left', padx=10)

    def build_generate_tab(self):
        frm = self.tab_generate
        content_frame = ttk.Frame(frm, padding=20)
        content_frame.pack(fill='both', expand=True)

        ttk.Label(content_frame, text='Password Name:', font=('Arial', 10)).pack(anchor='w', pady=(0, 5))
        self.name_var = tk.StringVar()
        ttk.Entry(content_frame, textvariable=self.name_var, font=('Arial', 10)).pack(fill='x', pady=(0, 15))

        length_frame = ttk.Frame(content_frame)
        length_frame.pack(fill='x', pady=(0, 20))
        ttk.Label(length_frame, text='Length:', font=('Arial', 10)).pack(side='left')
        self.length_var = tk.IntVar(value=12)
        for length in [12, 13, 14, 16, 20]:
            ttk.Radiobutton(length_frame, text=str(length), variable=self.length_var, value=length).pack(side='left', padx=10)

        ttk.Button(content_frame, text='Generate & Save', command=self.on_generate_and_save, style='Accent.TButton').pack(pady=(0, 20))

        ttk.Label(content_frame, text='Generated Password:', font=('Arial', 10)).pack(anchor='w', pady=(0, 5))
        self.generated_var = tk.StringVar()
        ttk.Entry(content_frame, textvariable=self.generated_var, state='readonly', font=('Arial', 10)).pack(fill='x')

    def build_settings_tab(self):
        frm = self.tab_settings
        content_frame = ttk.Frame(frm, padding=20)
        content_frame.pack(fill='both', expand=True)

        ttk.Label(content_frame, text='Theme:', font=('Arial', 10)).pack(anchor='w', pady=(0, 5))
        ttk.Checkbutton(content_frame, text='Dark Mode', variable=self.dark_mode, command=self.toggle_theme).pack(anchor='w')

        ttk.Label(content_frame, text='Storage Location:', font=('Arial', 10)).pack(anchor='w', pady=(15, 5))
        self.store_label = ttk.Label(content_frame, text=self.storage_path, wraplength=DEFAULT_WIDTH - 50, font=('Arial', 10))
        self.store_label.pack(anchor='w')
        ttk.Button(content_frame, text='Change Location...', command=self.change_location, style='TButton').pack(pady=10)
        ttk.Button(content_frame, text='Detect USB Drive', command=self.detect_pendrive, style='TButton').pack(pady=5)

        ttk.Label(content_frame, text='File Extension:', font=('Arial', 10)).pack(anchor='w', pady=(15, 5))
        ext_frame = ttk.Frame(content_frame)
        ext_frame.pack(fill='x')
        self.ext_var = tk.StringVar(value=self.extension)
        ttk.Entry(ext_frame, textvariable=self.ext_var, width=15, font=('Arial', 10)).pack(side='left')
        ttk.Button(ext_frame, text='Save Extension', command=self.save_extension, style='TButton').pack(side='left', padx=10)

        ttk.Label(content_frame, text='Tip:', font=('Arial', 10, 'bold')).pack(anchor='w', pady=(15, 5))
        ttk.Label(content_frame, text='For enhanced security, run this program directly from a USB drive.', font=('Arial', 10)).pack(anchor='w')

    def refresh_list(self):
        if not self.vault:
            return
        self.listbox.delete(0, tk.END)
        for safe, name in self.vault.list_items():
            self.listbox.insert(tk.END, f"{name}")
        self.safe_map = [s for s, _ in self.vault.list_items()]
        self.detail_name.config(text='Name: —')
        self.detail_created.config(text='Created: —')
        self.password_var.set('')

    def filter_list(self, *args):
        search_term = self.search_var.get().lower()
        self.listbox.delete(0, tk.END)
        filtered_items = [(s, n) for s, n in self.vault.list_items() if search_term in n.lower()]
        for safe, name in filtered_items:
            self.listbox.insert(tk.END, f"{name}")
        self.safe_map = [s for s, _ in filtered_items]

    def on_select(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        safe = self.safe_map[idx]
        payload = self.vault.read_password(safe)
        if not payload:
            messagebox.showerror("Error", "Unable to read password. The file may be corrupted.")
            return
        self.detail_name.config(text=f"Name: {payload.get('name')}")
        self.detail_created.config(text=f"Created: {payload.get('created_at')}")
        self.password_var.set(payload.get('password'))
        self.password_entry.config(show='*')

    def toggle_show(self):
        self.password_entry.config(show='' if self.show_var.get() else '*')

    def copy_password(self):
        pwd = self.password_var.get()
        if not pwd:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def delete_selected(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        safe = self.safe_map[idx]
        confirm = messagebox.askyesno("Confirm", "Are you sure you want to delete this password? This action cannot be undone.")
        if not confirm:
            return
        info = self.vault.index.pop(safe, None)
        if info:
            path = os.path.join(self.vault.storage_path, info['file'])
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
            self.vault._save_index()
            self.refresh_list()

    def on_generate_and_save(self):
        name = self.name_var.get().strip()
        if not name:
            messagebox.showwarning("Warning", "Please enter a name for the password.")
            return
        length = self.length_var.get()
        pwd = generate_password(length)
        self.generated_var.set(pwd)
        try:
            self.vault.save_password(name, pwd, ext=self.ext_var.get().strip() or DEFAULT_EXTENSION)
            messagebox.showinfo("Success", f"Password for '{name}' generated and saved successfully.")
            self.refresh_list()
            self.name_var.set('')
            self.generated_var.set('')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {e}")

    def toggle_theme(self):
        sv_ttk.set_theme("dark" if self.dark_mode.get() else "light")
        if platform.system() == "Windows":
            self.root.wm_attributes("-transparentcolor", "#2b2b2b" if self.dark_mode.get() else "#f0f0f0")

    def detect_pendrive(self):
        drives = _get_removable_drives()
        if not drives:
            messagebox.showinfo("No USB", "No removable devices (USB drives) detected.")
            return
        selected_drive = drives[0]
        new_path = str(selected_drive / APP_NAME)
        confirm = messagebox.askyesno(
            "USB Detected",
            f"A USB drive was found at '{selected_drive}'.\nWould you like to use it as the new storage location?\n\nNew path: {new_path}"
        )
        if confirm:
            self._perform_storage_change(new_path)

    def change_location(self):
        new = filedialog.askdirectory(title='Select New Storage Folder')
        if not new:
            return
        try:
            self._perform_storage_change(new)
            self.refresh_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change storage location: {e}")

    def _perform_storage_change(self, new_path: str):
        try:
            self.vault.change_storage(new_path)
            self.storage_path = new_path
            self.store_label.config(text=self.storage_path)
            messagebox.showinfo("Success", f"Storage location changed to:\n{new_path}")
            self.refresh_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change storage location: {e}")

    def save_extension(self):
        self.extension = self.ext_var.get().strip() or DEFAULT_EXTENSION
        messagebox.showinfo("Success", f"File extension set to {self.extension}")

if __name__ == '__main__':
    try:
        root = tk.Tk()
        app = PasswordManagerApp(root)
        root.mainloop()
    except Exception as e:
        print('Fatal error:', e)
