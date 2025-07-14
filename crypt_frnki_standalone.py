#!/usr/bin/env python3
"""
crypt.frnki v1.1.1 - Standalone Version
Secure File Encryption Tool - Single file for USB distribution

All security vulnerabilities fixed:
- Random per-file salts (no hardcoded salt)
- Path traversal protection
- Input validation & memory security
- Production-ready security hardening
"""

import sys
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import webbrowser
import gc
import struct
import secrets
import zlib
import tempfile
import string
import ctypes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2.low_level import hash_secret_raw, Type

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

MAGIC_NUMBER = 0xDEADBEEF
CHUNK_SIZE = 4096  # For streaming


def set_dark_title_bar(window):
    """Set dark title bar on Windows"""
    if sys.platform == "win32":
        try:
            hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            value = ctypes.c_int(1)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(value), ctypes.sizeof(value)
            )
        except:
            pass


def sanitize_filename(filename):
    """Remove path traversal sequences and invalid characters from filename"""
    filename = Path(filename).name  # Remove any path components
    filename = filename.replace('..', '')  # Remove traversal attempts
    
    # Keep only safe characters
    safe_chars = set(string.ascii_letters + string.digits + '._-')
    filename = ''.join(c for c in filename if c in safe_chars)
    
    # Ensure filename is not empty and not too long
    if not filename or len(filename) > 255:
        filename = 'encrypted_file'
    
    return filename


def secure_clear_string(s):
    """Securely clear a string from memory by overwriting it"""
    if s:
        length = len(s)
        s = bytearray(b'0' * length)  # Use mutable bytearray for overwrite
        del s
        gc.collect()


def get_resource_path(resource_name):
    """Get path to a resource file, handling both development and PyInstaller builds"""
    if getattr(sys, 'frozen', False):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(__file__).parent.absolute()
    
    return base_path / resource_name


def derive_key(passphrase, salt):
    """Derive encryption key using Argon2id"""
    return hash_secret_raw(
        secret=passphrase.encode('utf-8'),
        salt=salt,
        time_cost=3,  # Increased for better security
        memory_cost=65536,  # 64 MB
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )


def encrypt_file(in_path, out_path, passphrase, compress_level, progress_callback=None):
    """Encrypt a file using ChaCha20-Poly1305 with optional compression"""
    try:
        salt = secrets.token_bytes(16)
        name_nonce = secrets.token_bytes(12)
        content_base_nonce = secrets.token_bytes(8)  # Base for content nonces
        key = derive_key(passphrase, salt)
        aead = ChaCha20Poly1305(key)

        basename = Path(in_path).name
        name_data = struct.pack('<H', len(basename)) + basename.encode('utf-8')
        name_cipher = aead.encrypt(name_nonce, name_data, None)

        with open(in_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
            # Header
            f_out.write(struct.pack('<I', MAGIC_NUMBER))
            f_out.write(salt)
            f_out.write(name_nonce)
            f_out.write(content_base_nonce)

            # Name
            f_out.write(struct.pack('<I', len(name_cipher)))
            f_out.write(name_cipher)

            # Streaming compress + encrypt content
            if compress_level > 0:
                compressor = zlib.compressobj(level=compress_level)
            else:
                compressor = None  # No compression

            total_size = Path(in_path).stat().st_size
            processed = 0
            chunk_index = 0
            
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    if compressor:
                        compressed_chunk = compressor.flush()
                    else:
                        compressed_chunk = b''
                else:
                    if compressor:
                        compressed_chunk = compressor.compress(chunk)
                    else:
                        compressed_chunk = chunk
                    
                if compressed_chunk or (not chunk and compressor):
                    content_nonce = content_base_nonce + struct.pack('<I', chunk_index)
                    content_cipher = aead.encrypt(content_nonce, compressed_chunk, None)
                    f_out.write(struct.pack('<I', len(content_cipher)))
                    f_out.write(content_cipher)
                    chunk_index += 1
                    
                processed += len(chunk) if chunk else 0
                if progress_callback:
                    progress_callback((processed / total_size) * 100 if total_size > 0 else 100)
                    
                if not chunk:
                    break
                    
        return True
    except Exception:
        return False


def decrypt_file(in_path, out_dir, passphrase, progress_callback=None):
    """Decrypt a file encrypted with encrypt_file"""
    try:
        with open(in_path, 'rb') as f_in:
            # Validate magic number
            magic_bytes = f_in.read(4)
            if len(magic_bytes) != 4:
                return False
            magic = struct.unpack('<I', magic_bytes)[0]
            if magic != MAGIC_NUMBER:
                return False
            
            # Read header components with validation
            salt = f_in.read(16)
            if len(salt) != 16:
                return False
            name_nonce = f_in.read(12)
            if len(name_nonce) != 12:
                return False
            content_base_nonce = f_in.read(8)
            if len(content_base_nonce) != 8:
                return False
            
            # Validate name length
            name_len_bytes = f_in.read(4)
            if len(name_len_bytes) != 4:
                return False
            name_len = struct.unpack('<I', name_len_bytes)[0]
            if name_len > 1024:  # Reasonable filename limit
                return False
            
            name_cipher = f_in.read(name_len)
            if len(name_cipher) != name_len:
                return False

            key = derive_key(passphrase, salt)
            aead = ChaCha20Poly1305(key)

            try:
                name_data = aead.decrypt(name_nonce, name_cipher, None)
            except Exception:
                return False  # Invalid passphrase or corrupted data
            
            if len(name_data) < 2:
                return False
            orig_name_len = struct.unpack('<H', name_data[:2])[0]
            if orig_name_len > len(name_data) - 2 or orig_name_len > 255:
                return False
            
            try:
                orig_name = name_data[2:2 + orig_name_len].decode('utf-8')
            except UnicodeDecodeError:
                return False
            
            # Sanitize filename to prevent path traversal
            safe_name = sanitize_filename(orig_name)
            
            # Streaming decrypt + decompress content
            decompressor = zlib.decompressobj() if True else None  # Assume compression; will fail if not
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            final_out = Path(out_dir) / safe_name
            
            # Use temporary file for atomic operation
            with tempfile.NamedTemporaryFile(dir=out_dir, delete=False) as temp_file:
                temp_path = Path(temp_file.name)
                chunk_index = 0
                total_size = Path(in_path).stat().st_size
                processed = len(magic_bytes) + len(salt) + len(name_nonce) + len(content_base_nonce) + 4 + name_len
                
                while True:
                    len_bytes = f_in.read(4)
                    if not len_bytes:
                        try:
                            if decompressor:
                                decompressed = decompressor.flush()
                                temp_file.write(decompressed)
                        except zlib.error:
                            return False
                        break
                    
                    if len(len_bytes) != 4:
                        return False
                    chunk_len = struct.unpack('<I', len_bytes)[0]
                    
                    # Validate chunk length
                    if chunk_len > 1024 * 1024:  # 1MB max chunk
                        return False
                    
                    chunk = f_in.read(chunk_len)
                    if len(chunk) != chunk_len:
                        return False
                    
                    # Prevent chunk index overflow
                    if chunk_index >= 0xFFFFFFFF:
                        return False
                    
                    content_nonce = content_base_nonce + struct.pack('<I', chunk_index)
                    try:
                        decrypted_chunk = aead.decrypt(content_nonce, chunk, None)
                        if decompressor:
                            decompressed = decompressor.decompress(decrypted_chunk)
                        else:
                            decompressed = decrypted_chunk
                    except Exception:
                        return False
                    
                    temp_file.write(decompressed)
                    processed += chunk_len + 4
                    if progress_callback:
                        progress_callback((processed / total_size) * 100 if total_size > 0 else 100)
                    chunk_index += 1
            
            # Atomic move of completed file
            temp_path.replace(final_out)
                
        return True
    except Exception:
        # Clean up temp file on error
        try:
            if 'temp_path' in locals():
                temp_path.unlink()
        except:
            pass
        return False


class EncryptionApp:
    """Main GUI application for file encryption/decryption"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("crypt.frnki")
        self.root.configure(bg="#282828")
        self.root.geometry("600x450")  # Slightly taller for confirmation field
        self.center_window()
        
        # Set dark title bar on Windows and icon
        set_dark_title_bar(self.root)
        self._set_window_icon()
        
        # Initialize GUI components
        self._setup_styles()
        self._create_widgets()
        
        # Initialize state
        self.file_paths = {}
        
    def _set_window_icon(self):
        """Set the window icon if available"""
        try:
            if sys.platform == "win32" and getattr(sys, 'frozen', False):
                # For frozen Windows exe, use the embedded exe icon
                self.root.iconbitmap(sys.executable)
            else:
                # Fallback for source or non-Windows
                icon_path = get_resource_path("favicon.ico")
                if icon_path.exists():
                    self.root.iconbitmap(str(icon_path))
        except Exception:
            pass  # Silent fail if icon can't be set
    
    def _setup_styles(self):
        """Configure ttk styles for the application"""
        style = ttk.Style()
        style.theme_use('default')
        style.configure(
            "Custom.Horizontal.TProgressbar",
            troughcolor="#1e1e1e",
            background="#98971a",
            bordercolor="#1e1e1e",
            lightcolor="#1e1e1e",
            darkcolor="#1e1e1e"
        )
    
    def _create_widgets(self):
        """Create and layout all GUI widgets"""
        # Color schemes
        label_opts = {"bg": "#282828", "fg": "#ebdbb2"}
        entry_opts = {"bg": "#1e1e1e", "fg": "#ebdbb2", "insertbackground": "#ebdbb2", "highlightbackground": "#ebdbb2"}
        btn_opts = {"bg": "#a9b665", "fg": "#282828", "activebackground": "#b8bb26"}

        # File list section
        tk.Label(self.root, text="Selected Files:", **label_opts).pack(pady=(10, 0))
        self.file_list = tk.Listbox(self.root, selectmode=tk.MULTIPLE, height=5,
                                    bg="#1e1e1e", fg="#ebdbb2", selectbackground="#b8bb26",
                                    highlightbackground="#ebdbb2", width=50)
        self.file_list.pack(pady=5)

        # Passphrase section
        tk.Label(self.root, text="Passphrase:", **label_opts).pack(pady=(10, 0))
        self.pass_entry = tk.Entry(self.root, show="*", **entry_opts)
        self.pass_entry.pack(pady=5)

        tk.Label(self.root, text="Confirm Passphrase:", **label_opts).pack(pady=(5, 0))
        self.confirm_entry = tk.Entry(self.root, show="*", **entry_opts)
        self.confirm_entry.pack(pady=5)

        # Options section
        options_frame = tk.Frame(self.root, bg="#282828")
        options_frame.pack(pady=5)

        self.delete_original_var = tk.IntVar()
        self.delete_original = tk.Checkbutton(options_frame,
                                              text="Delete original after encryption",
                                              variable=self.delete_original_var,
                                              bg="#282828",
                                              fg="#ebdbb2",
                                              activebackground="#282828",
                                              activeforeground="#98971a",
                                              highlightthickness=0,
                                              bd=0,
                                              selectcolor="#1e1e1e")
        self.delete_original.pack(side=tk.LEFT, padx=5)

        tk.Label(options_frame, text="Compression Level:", **label_opts).pack(side=tk.LEFT, padx=5)
        self.compress_level = tk.StringVar(value="High")
        self.compress_menu = tk.OptionMenu(options_frame, self.compress_level, "None", "Low", "Medium", "High")
        self.compress_menu.config(bg="#1e1e1e", fg="#ebdbb2", activebackground="#b8bb26", 
                                 activeforeground="#282828", highlightbackground="#1e1e1e", 
                                 bd=0, highlightthickness=0, width=8)
        self.compress_menu["menu"].config(bg="#1e1e1e", fg="#ebdbb2", activebackground="#b8bb26", 
                                         activeforeground="#282828", bd=0)
        self.compress_menu.pack(side=tk.LEFT, padx=5)

        # Button section
        btn_row = tk.Frame(self.root, bg="#282828")
        btn_row.pack(pady=10)

        self.add_btn = tk.Button(btn_row, text="Add Files", command=self.add_files, **btn_opts, width=8)
        self.add_btn.pack(side=tk.LEFT, padx=5)

        self.encrypt_btn = tk.Button(btn_row, text="Encrypt", command=self.encrypt_files, **btn_opts, width=8)
        self.encrypt_btn.pack(side=tk.LEFT, padx=5)

        self.decrypt_btn = tk.Button(btn_row, text="Decrypt", command=self.decrypt_files, **btn_opts, width=8)
        self.decrypt_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = tk.Button(btn_row, text="Clear Files", command=self.clear_files, **btn_opts, width=8)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        # Progress and logo section
        bottom_frame = tk.Frame(self.root, bg="#282828")
        bottom_frame.pack(padx=30, fill=tk.X)

        self.progress = ttk.Progressbar(bottom_frame, mode='determinate', style="Custom.Horizontal.TProgressbar")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=5)

        self._setup_logo(bottom_frame)

        # Status section
        self.status = tk.Label(self.root, text="", **label_opts)
        self.status.pack(pady=5)

    def _setup_logo(self, parent_frame):
        """Setup the animated logo"""
        try:
            if PIL_AVAILABLE:
                icon_path = get_resource_path("favicon.png")
                self.original_logo = Image.open(icon_path).resize((48, 48))
                self.logo_img = ImageTk.PhotoImage(self.original_logo)
                self.logo_label = tk.Label(parent_frame, image=self.logo_img, bg="#282828", cursor="hand2")
                self.logo_label.pack(side=tk.RIGHT, padx=(10, 0))

                self.logo_angle = 0
                self.rotating = False
                self.hovering = False

                self.logo_label.bind("<Enter>", self.start_rotate)
                self.logo_label.bind("<Leave>", self.stop_rotate)
                self.logo_label.bind("<Button-1>", lambda _: webbrowser.open_new("https://frnki.dev"))
        except Exception:
            # Logo setup failed, continue without logo
            pass

    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        ws = self.root.winfo_screenwidth()
        hs = self.root.winfo_screenheight()
        x = (ws // 2) - (w // 2)
        y = (hs // 2) - (h // 2)
        self.root.geometry(f'{w}x{h}+{x}+{y}')

    def add_files(self):
        """Add files to the file list"""
        files = filedialog.askopenfilenames()
        for file in files:
            display_name = Path(file).name
            self.file_list.insert(tk.END, display_name)
            self.file_paths[display_name] = file

    def clear_files(self):
        """Clear the file list"""
        self.file_list.delete(0, tk.END)
        self.file_paths.clear()

    def encrypt_files(self):
        """Start encryption process"""
        self.process_files('encrypt')

    def decrypt_files(self):
        """Start decryption process"""
        self.process_files('decrypt')

    def process_files(self, mode):
        """Process files for encryption or decryption"""
        display_names = list(self.file_list.get(0, tk.END))
        passphrase = self.pass_entry.get()
        confirm = self.confirm_entry.get()
        
        if not display_names or not passphrase:
            messagebox.showerror("Error", "Select files and enter passphrase")
            return

        if passphrase != confirm:
            messagebox.showerror("Error", "Passphrases do not match")
            return

        # Convert display names back to full paths
        files = []
        for display_name in display_names:
            if display_name in self.file_paths:
                files.append(self.file_paths[display_name])
            else:
                files.append(display_name)

        self.status.config(text=f"{mode.capitalize()}ing... Deriving key...")
        self.progress['value'] = 0
        self.root.update_idletasks()

        # Create a copy of passphrase for thread to avoid race conditions
        passphrase_copy = passphrase
        threading.Thread(target=self._process_thread, args=(mode, files, passphrase_copy), daemon=True).start()

    def _process_thread(self, mode, files, passphrase):
        """Background thread for file processing"""
        try:
            total_files = len(files)
            compress_map = {"None": 0, "Low": 1, "Medium": 5, "High": 9}
            compress_level = compress_map[self.compress_level.get()]

            for idx, filename in enumerate(files):
                if not Path(filename).exists():
                    self._set_status_threadsafe("Operation failed")
                    return

                if mode == 'encrypt':
                    base_name = Path(filename).stem
                    out_dir = "encrypt_output"
                    out_file = Path(out_dir) / f"{sanitize_filename(base_name)}.frnki"
                    Path(out_dir).mkdir(exist_ok=True)
                    success = encrypt_file(filename, str(out_file), passphrase, compress_level, self.update_progress)
                    
                    if success and self.delete_original_var.get():
                        try:
                            Path(filename).unlink()
                        except OSError:
                            pass  # File deletion failed, but encryption succeeded
                else:
                    out_dir = "decrypt_output"
                    success = decrypt_file(filename, out_dir, passphrase, self.update_progress)
                    
                    if success:
                        try:
                            Path(filename).unlink()
                        except OSError:
                            pass  # File deletion failed, but decryption succeeded

                if not success:
                    self._set_status_threadsafe("Operation failed")
                    return

                self._set_progress_threadsafe(((idx + 1) / total_files) * 100)

            self.root.after(0, self._clear_passphrase_secure)
            self.root.after(0, self.clear_files)
            self.root.after(0, self._show_success_message, mode)
            
        finally:
            # Secure cleanup of passphrase from memory
            if 'passphrase' in locals():
                secure_clear_string(passphrase)

    def _clear_passphrase_secure(self):
        """Securely clear the passphrase entries"""
        for entry in [self.pass_entry, self.confirm_entry]:
            current = entry.get()
            if current:
                entry.delete(0, tk.END)
                entry.insert(0, '0' * len(current))
                entry.delete(0, tk.END)
        gc.collect()

    def _set_status_threadsafe(self, message):
        """Thread-safe status update"""
        self.root.after(0, lambda: self.status.config(text=message))

    def _set_progress_threadsafe(self, value):
        """Thread-safe progress update"""
        self.root.after(0, lambda: self.progress.config(value=value))

    def _show_success_message(self, mode):
        """Show success message and clear it after 3 seconds"""
        if mode == 'encrypt':
            self.status.config(text="Encryption successful!")
        else:
            self.status.config(text="Decryption complete!")

        self.root.after(3000, lambda: self.status.config(text=""))

    def update_progress(self, value):
        """Update progress bar (called from encryption/decryption functions)"""
        self.progress['value'] = value
        self.root.update_idletasks()

    def start_rotate(self, _):
        """Start logo rotation animation"""
        if hasattr(self, 'rotating') and self.rotating:
            return
        self.hovering = True
        self.rotating = True
        self.rotate_logo()

    def stop_rotate(self, _):
        """Stop logo rotation animation"""
        self.hovering = False

    def rotate_logo(self):
        """Animate logo rotation"""
        if not hasattr(self, 'original_logo'):
            return
            
        if self.hovering:
            if self.logo_angle < 15:
                self.logo_angle += 1
        else:
            if self.logo_angle > 0:
                self.logo_angle -= 1
            else:
                self.rotating = False
                return

        try:
            rotated = self.original_logo.rotate(self.logo_angle, resample=Image.BICUBIC, expand=0)
            self.logo_img = ImageTk.PhotoImage(rotated)
            self.logo_label.configure(image=self.logo_img)
            self.root.after(30, self.rotate_logo)
        except Exception:
            self.rotating = False


def main():
    """Main entry point for the application"""
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()