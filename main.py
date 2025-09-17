import os
import platform
import base64
import secrets
import string
import time
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog, Listbox
import sv_ttk
import json

APP_NAME = "PasswordStore"
HOME = Path.home()

DEFAULT_WIDTH = 700
DEFAULT_HEIGHT = 600

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
    if system == "Linux" or system == "Darwin": # macOS
        # Locais comuns de montagem, incluindo subpastas de usuário
        for mount_point in ('/media', '/run/media', '/mnt'):
            if os.path.isdir(mount_point):
                for entry in os.listdir(mount_point):
                    path_lvl1 = Path(mount_point) / entry
                    if path_lvl1.is_dir() and os.access(path_lvl1, os.W_OK):
                        drives.append(path_lvl1) # Adiciona /media/user
                        for sub_entry in os.listdir(path_lvl1): # Procura em /media/user/PENDRIVE
                            path_lvl2 = path_lvl1 / sub_entry
                            if path_lvl2.is_dir() and os.access(path_lvl2, os.W_OK):
                                drives.append(path_lvl2)
    elif system == "Windows":
        for drive in (f"{chr(c)}:" for c in range(ord('D'), ord('Z') + 1)):
            if os.path.isdir(drive):
                drives.append(Path(drive))
    return drives

DEFAULT_STORE = _get_default_storage_path()
DEFAULT_EXTENSION = ".mcdal"
SALT_NAME = "salt.bin"
INDEX_NAME = "index.json" # Agora em texto plano

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

    if length >= 4:
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
                self.index = {} # Arquivo corrompido ou vazio, começa um novo.
        else:
            self.index = {}

        self._reconcile_files()

    def _reconcile_files(self):
        """Garante que o índice e os arquivos na pasta estejam sincronizados."""
        try:
            files_in_dir = {f for f in os.listdir(self.storage_path) if f.endswith(DEFAULT_EXTENSION)}
        except FileNotFoundError:
            files_in_dir = set()

        indexed_files = {v['file'] for v in self.index.values()}

        # Adiciona ao índice arquivos que estão na pasta mas não no índice
        missing_from_index = files_in_dir - indexed_files
        if missing_from_index:
            for filename in missing_from_index:
                safe_name = filename.replace(DEFAULT_EXTENSION, '')
                display_name = safe_name # Fallback name
                ts = 0 # Default timestamp
                try:
                    with open(os.path.join(self.storage_path, filename), 'r', encoding='utf-8') as f:
                        payload = json.load(f)
                        display_name = payload.get('name', safe_name)
                except (json.JSONDecodeError, OSError, KeyError):
                    pass # Usa o nome do arquivo como fallback se a leitura falhar
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
        data = json.dumps(payload).encode()
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=4)

        self.index[safe] = {
            'file': filename,
            'display_name': name,
            'ts': time.time()
        }
        self._save_index()

    def list_items(self):
        items = [(k, v['display_name']) for k, v in sorted(self.index.items(), key=lambda x: x[1]['ts'], reverse=True)]
        return items

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
        # Copia o arquivo de índice para o novo local
        if os.path.exists(self.index_path):
            with open(self.index_path, 'r', encoding='utf-8') as src, open(os.path.join(new_path, INDEX_NAME), 'w', encoding='utf-8') as dst:
                dst.write(src.read())
        self.storage_path = new_path
        self.index_path = os.path.join(self.storage_path, INDEX_NAME)

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        root.title("Gerador de Senhas")
        root.geometry(f"{DEFAULT_WIDTH}x{DEFAULT_HEIGHT}")
        root.resizable(False, False)

        # Aplica o tema moderno e ativa o efeito de desfoque (se disponível no SO)
        sv_ttk.set_theme("dark")

        # Deixa a janela transparente para o efeito de desfoque aparecer
        if platform.system() == "Windows":
            root.wm_attributes("-transparentcolor", "#2b2b2b")

        self.storage_path = DEFAULT_STORE
        self.extension = DEFAULT_EXTENSION
        self.vault = None
        self.dark_mode = tk.BooleanVar(value=False)

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=8, pady=8)

        self.tab_passwords = ttk.Frame(self.notebook)
        self.tab_generate = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_passwords, text='Cofre')
        self.notebook.add(self.tab_generate, text='Gerar Nova Senha')
        self.notebook.add(self.tab_settings, text='Opções')

        self.build_passwords_tab()
        self.build_generate_tab()
        self.build_settings_tab()

        self.initialize_vault()

        root.bind('<F5>', lambda e: self.refresh_list())

    def initialize_vault(self):
        ensure_storage(self.storage_path)
        try:
            self.vault = Vault(self.storage_path)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao inicializar cofre: {e}")
            self.root.destroy(); return
        self.refresh_list()

    def build_passwords_tab(self):
        frm = self.tab_passwords
        frm.columnconfigure(1, weight=1)

        left = ttk.Frame(frm)
        left.grid(row=0, column=0, sticky='nsw', padx=(8,4), pady=8)
        right = ttk.Frame(frm)
        right.grid(row=0, column=1, sticky='nsew', padx=(4,8), pady=8)

        ttk.Label(left, text='Itens salvos:').pack(anchor='w')
        self.listbox = tk.Listbox(left, width=30, height=22)
        self.listbox.pack(side='left', fill='y')
        self.listbox.bind('<<ListboxSelect>>', lambda e: self.on_select())

        scrollbar = ttk.Scrollbar(left, orient='vertical', command=self.listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self.listbox.config(yscrollcommand=scrollbar.set)

        ttk.Label(right, text='Detalhes:').pack(anchor='w')
        self.detail_name = ttk.Label(right, text='Nome: —')
        self.detail_name.pack(anchor='w', pady=(4,2))
        self.detail_created = ttk.Label(right, text='Criado: —')
        self.detail_created.pack(anchor='w', pady=(0,8))

        pwd_frame = ttk.Frame(right)
        pwd_frame.pack(fill='x')
        self.password_var = tk.StringVar(value='')
        self.password_entry = ttk.Entry(pwd_frame, textvariable=self.password_var, show='*', width=30)
        self.password_entry.pack(side='left', fill='x', expand=True)
        self.show_var = tk.BooleanVar(value=True) # Mostrar senhas por padrão
        ttk.Checkbutton(pwd_frame, text='Mostrar', variable=self.show_var, command=self.toggle_show).pack(side='left', padx=6)

        btn_frame = ttk.Frame(right)
        btn_frame.pack(fill='x', pady=8)
        ttk.Button(btn_frame, text='Copiar para área de transferência', command=self.copy_password).pack(side='left')
        ttk.Button(btn_frame, text='Deletar', command=self.delete_selected).pack(side='left', padx=6)

    def build_generate_tab(self):
        frm = self.tab_generate
        ttk.Label(frm, text='Nome (identificador):').pack(anchor='w', padx=8, pady=(8,2))
        self.name_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.name_var).pack(fill='x', padx=8)

        length_frame = ttk.Frame(frm)
        length_frame.pack(fill='x', padx=8, pady=8)
        ttk.Label(length_frame, text='Comprimento:').pack(side='left')
        self.length_var = tk.IntVar(value=12)
        ttk.Radiobutton(length_frame, text='12', variable=self.length_var, value=12).pack(side='left', padx=6)
        ttk.Radiobutton(length_frame, text='13', variable=self.length_var, value=13).pack(side='left', padx=6)
        ttk.Radiobutton(length_frame, text='14', variable=self.length_var, value=14).pack(side='left', padx=6)

        ttk.Button(frm, text='Gerar e Salvar Automaticamente', command=self.on_generate_and_save).pack(padx=8, pady=(0,8))

        ttk.Label(frm, text='Senha gerada:').pack(anchor='w', padx=8)
        self.generated_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.generated_var, width=40).pack(fill='x', padx=8)

    def build_settings_tab(self):
        frm = self.tab_settings
        ttk.Label(frm, text='Tema:').pack(anchor='w', padx=8, pady=(8,2))
        ttk.Checkbutton(frm, text='Modo escuro', variable=self.dark_mode, command=self.toggle_theme).pack(anchor='w', padx=8)

        ttk.Label(frm, text='Local de armazenamento:').pack(anchor='w', padx=8, pady=(12,2))
        self.store_label = ttk.Label(frm, text=self.storage_path)
        self.store_label.pack(anchor='w', padx=8)
        ttk.Button(frm, text='Alterar local...', command=self.change_location).pack(padx=8, pady=6)
        ttk.Button(frm, text='Detectar Pendrive', command=self.detect_pendrive).pack(padx=8, pady=6)

        ttk.Label(frm, text='Extensão dos arquivos:').pack(anchor='w', padx=8, pady=(12,2))
        self.ext_var = tk.StringVar(value=self.extension)
        ttk.Entry(frm, textvariable=self.ext_var, width=12).pack(anchor='w', padx=8)
        ttk.Button(frm, text='Salvar extensão', command=self.save_extension).pack(padx=8, pady=6)

        ttk.Label(frm, text='DICA:').pack(anchor='w', padx=8, pady=(12,2))
        ttk.Label(frm, text='coloque o codigo no pendrave e coloque paraa  roda para maior segurança. futuramente eu vou deixa isso automatico ').pack(anchor='w', padx=8)

    def refresh_list(self):
        if not self.vault:
            return
        self.listbox.delete(0, tk.END)
        for safe, name in self.vault.list_items():
            self.listbox.insert(tk.END, f"{name}  ")
        self.safe_map = [s for s, _ in self.vault.list_items()]
        self.detail_name.config(text='Nome: —')
        self.detail_created.config(text='Criado: —')
        self.password_var.set('')

    def on_select(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        safe = self.safe_map[idx]
        payload = self.vault.read_password(safe)
        if not payload:
            messagebox.showerror("Erro", "Não foi possível ler a senha. Talvez a chave esteja incorreta ou arquivo corrompido.")
            return
        self.detail_name.config(text=f"Nome: {payload.get('name')}")
        created = payload.get('created_at')
        self.detail_created.config(text=f"Criado: {created}")
        self.password_var.set(payload.get('password'))
        self.toggle_show() # Atualiza a visibilidade da senha

    def toggle_show(self):
        if self.show_var.get():
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='*')

    def copy_password(self):
        pwd = self.password_var.get()
        if not pwd:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        messagebox.showinfo("Copiado", "Senha copiada para a área de transferência.")

    def delete_selected(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        safe = self.safe_map[idx]
        confirm = messagebox.askyesno("Confirmar", "Deseja deletar esta senha? A ação não pode ser desfeita.")
        if not confirm:
            return
        info = self.vault.index.pop(safe, None)
        if info:
            path = os.path.join(self.vault.storage_path, info['file'])
            try:
                if os.path.exists(path): os.remove(path)
            except Exception:
                pass
            self.vault._save_index()
            self.refresh_list()

    def on_generate_and_save(self):
        name = self.name_var.get().strip()
        if not name:
            messagebox.showwarning("Atenção", "Informe um nome (identificador) antes de gerar a senha.")
            return
        length = self.length_var.get()
        pwd = generate_password(length)
        self.generated_var.set(pwd)
        try:
            self.vault.save_password(name, pwd, ext=self.ext_var.get().strip() or DEFAULT_EXTENSION)
            messagebox.showinfo("Salvo", f"Senha para '{name}' foi gerada e salva com sucesso.")
            self.refresh_list()
            self.name_var.set('')
            self.generated_var.set('')
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível salvar a senha: {e}")

    def toggle_theme(self):
        if self.dark_mode.get():
            self.root.configure(bg='#2b2b2b')
        else:
            self.root.configure(bg='#f0f0f0')

    def detect_pendrive(self):
        drives = _get_removable_drives()
        if not drives:
            messagebox.showinfo("Nenhum Pendrive", "Nenhum dispositivo removível (pendrive) foi detectado.")
            return

        # Por simplicidade, vamos usar o primeiro pendrive detectado.
        # Uma melhoria futura poderia ser mostrar uma lista para o usuário escolher.
        selected_drive = drives[0]
        new_path = str(selected_drive / APP_NAME)

        confirm = messagebox.askyesno(
            "Pendrive Detectado",
            f"Um pendrive foi encontrado em '{selected_drive}'.\nDeseja usá-lo como o novo local de armazenamento?\n\nO novo caminho será: {new_path}"
        )
        if confirm:
            self._perform_storage_change(new_path)

    def change_location(self):
        new = filedialog.askdirectory(title='Escolha nova pasta de armazenamento')
        if not new:
            return
        try:
            self._perform_storage_change(new)
            self.refresh_list()
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível alterar local: {e}")

    def _perform_storage_change(self, new_path: str):
        try:
            self.vault.change_storage(new_path)
            self.storage_path = new_path
            self.store_label.config(text=self.storage_path)
            messagebox.showinfo("Sucesso", f"O local de armazenamento foi alterado para:\n{new_path}")
            self.refresh_list()
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível alterar o local: {e}")

    def save_extension(self):
        self.extension = self.ext_var.get().strip() or DEFAULT_EXTENSION
        messagebox.showinfo("Pronto", f"Extensão definida para {self.extension}")

if __name__ == '__main__':
    try:
        root = tk.Tk()
        app = PasswordManagerApp(root)
        root.mainloop()
    except Exception as e:
        print('Erro fatal:', e)
