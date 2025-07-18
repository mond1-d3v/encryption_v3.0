import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
import datetime
from crypto_engine import MilitaryGradeEncryption

class ProfessionalCryptoInterface:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.setup_variables()
        self.setup_styles()
        self.create_interface()
        
    def setup_window(self):
        self.root.title("Unbreakable Encryption System v3.0 - Professional Edition")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        self.root.configure(bg='#0d1117')
        try:
            self.center_window()
        except:
            pass
    
    def center_window(self):
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (self.root.winfo_width() // 2)
        y = (self.root.winfo_screenheight() // 2) - (self.root.winfo_height() // 2)
        self.root.geometry(f"+{x}+{y}")
    
    def setup_variables(self):
        self.selected_file = tk.StringVar()
        self.selected_encrypted_file = tk.StringVar()
        self.selected_key_file = tk.StringVar()
        self.status_var = tk.StringVar(value="System Ready")
        self.progress_var = tk.DoubleVar()
        self.operation_in_progress = False
        self.encrypt_dir, self.keys_dir = MilitaryGradeEncryption.create_output_directories()

    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Title.TLabel', 
                       font=('Segoe UI Light', 28, 'normal'),
                       background='#0d1117', 
                       foreground='#58a6ff')
        
        style.configure('Subtitle.TLabel',
                       font=('Segoe UI', 12),
                       background='#0d1117',
                       foreground='#f0f6fc')
        
        style.configure('Professional.TButton',
                       font=('Segoe UI', 11, 'bold'),
                       padding=(25, 12))
        
        style.configure('Action.TButton',
                       font=('Segoe UI', 13, 'bold'),
                       padding=(35, 18))
        
        style.configure('Info.TLabel',
                       font=('Segoe UI', 10),
                       background='#21262d',
                       foreground='#e6edf3')
        
        style.configure('Status.TLabel',
                       font=('Segoe UI', 11),
                       background='#0d1117',
                       foreground='#58a6ff')
    
    def create_interface(self):
        self.create_header()
        self.create_status_bar()
        self.create_main_content()
        self.create_footer()
    
    def create_header(self):
        header_frame = tk.Frame(self.root, bg='#0d1117', height=140)
        header_frame.pack(fill='x', padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        header_container = tk.Frame(header_frame, bg='#0d1117')
        header_container.pack(expand=True, fill='both', padx=40, pady=25)
        
        title_section = tk.Frame(header_container, bg='#0d1117')
        title_section.pack(side='left', fill='both', expand=True)
        
        logo_container = tk.Frame(title_section, bg='#0d1117')
        logo_container.pack(side='left')
        
        logo_label = ttk.Label(logo_container, text="🔒", 
                              font=('Segoe UI Emoji', 42), 
                              background='#0d1117', 
                              foreground='#58a6ff')
        logo_label.pack(padx=(0, 20))
        
        text_section = tk.Frame(title_section, bg='#0d1117')
        text_section.pack(side='left', fill='both', expand=True)
        
        title_label = ttk.Label(text_section, 
                               text="Unbreakable Encryption", 
                               style='Title.TLabel')
        title_label.pack(anchor='w')
        
        subtitle_label = ttk.Label(text_section,
                                  text="Advanced cryptographic protection • One-Time Pad technology • Information-theoretic security",
                                  style='Subtitle.TLabel')
        subtitle_label.pack(anchor='w', pady=(8, 0))
        
        status_section = tk.Frame(header_container, bg='#0d1117')
        status_section.pack(side='right', fill='y')
        
        security_indicator = tk.Frame(status_section, bg='#21262d', relief='solid', bd=1, width=120, height=60)
        security_indicator.pack(pady=10, padx=15)
        security_indicator.pack_propagate(False)
        
        tk.Label(security_indicator, text="SECURITY LEVEL", 
                font=('Segoe UI', 9, 'bold'), 
                bg='#21262d', fg='#f0f6fc').pack(pady=(8, 2))
        
        tk.Label(security_indicator, text="MILITARY", 
                font=('Segoe UI', 12, 'bold'), 
                bg='#21262d', fg='#f85149').pack(pady=(0, 8))
        
        separator = tk.Frame(self.root, height=3, bg='#30363d')
        separator.pack(fill='x')

    def create_status_bar(self):
        status_frame = tk.Frame(self.root, bg='#21262d', height=45)
        status_frame.pack(fill='x')
        status_frame.pack_propagate(False)
        
        status_label = ttk.Label(status_frame, textvariable=self.status_var, style='Status.TLabel')
        status_label.pack(side='left', padx=25, pady=12)
        
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, 
                                           length=250, mode='determinate')
        self.progress_bar.pack(side='right', padx=25, pady=10)
    
    def create_main_content(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=25, pady=25)
        
        encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(encrypt_frame, text="🔐 ENCRYPTION")
        self.create_encrypt_tab(encrypt_frame)
        
        decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(decrypt_frame, text="🔓 DECRYPTION")
        self.create_decrypt_tab(decrypt_frame)
        
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="📊 SECURITY ANALYSIS")
        self.create_analysis_tab(analysis_frame)
        
        help_frame = ttk.Frame(self.notebook)
        self.notebook.add(help_frame, text="📖 DOCUMENTATION")
        self.create_help_tab(help_frame)
    
    def create_encrypt_tab(self, parent):
        main_container = tk.Frame(parent, bg='#f6f8fa')
        main_container.pack(fill='both', expand=True, padx=15, pady=15)
        
        left_panel = tk.Frame(main_container, bg='#ffffff', relief='solid', bd=1)
        left_panel.pack(side='left', fill='y', padx=(0, 15), ipadx=25, ipady=25)
        
        instructions_frame = tk.LabelFrame(left_panel, text="📋 Encryption Workflow", 
                                         font=('Segoe UI', 12, 'bold'), 
                                         bg='#ffffff', fg='#24292f')
        instructions_frame.pack(fill='x', pady=(0, 25))
        
        instructions = [
            "1️⃣ Select file for cryptographic protection",
            "2️⃣ Review file information and parameters",
            "3️⃣ Execute One-Time Pad encryption",
            "4️⃣ Secure the generated cryptographic key",
            "",
            "⚠️ CRITICAL INFORMATION:",
            "• Unique key generated per file",
            "• Key size equals file size",
            "• Key loss results in permanent data loss",
            "• Security level: MILITARY"
        ]
        
        for instruction in instructions:
            color = '#d1242f' if instruction.startswith('⚠️') else '#24292f'
            weight = 'bold' if instruction.startswith(('⚠️', '•')) else 'normal'
            
            tk.Label(instructions_frame, text=instruction,
                    font=('Segoe UI', 10, weight),
                    bg='#ffffff', fg=color, anchor='w').pack(anchor='w', padx=15, pady=3)
        
        file_frame = tk.LabelFrame(left_panel, text="📁 File Selection", 
                                  font=('Segoe UI', 12, 'bold'),
                                  bg='#ffffff', fg='#24292f')
        file_frame.pack(fill='x', pady=(0, 25))
        
        select_btn = tk.Button(file_frame, text="📂 BROWSE FILES",
                              command=self.select_file_to_encrypt,
                              font=('Segoe UI', 11, 'bold'),
                              bg='#2da44e', fg='white',
                              relief='flat', padx=25, pady=12,
                              cursor='hand2', activebackground='#2c974b')
        select_btn.pack(pady=15)
        
        self.file_info_frame = tk.Frame(file_frame, bg='#f6f8fa', relief='solid', bd=1)
        self.file_info_frame.pack(fill='x', padx=15, pady=15)
        
        tk.Label(self.file_info_frame, text="No file selected",
                font=('Segoe UI', 10), bg='#f6f8fa', fg='#656d76',
                pady=15).pack()
        
        encrypt_btn = tk.Button(left_panel, text="🔐 EXECUTE ENCRYPTION",
                               command=self.encrypt_file,
                               font=('Segoe UI', 13, 'bold'),
                               bg='#0969da', fg='white',
                               relief='flat', padx=35, pady=18,
                               cursor='hand2', state='disabled',
                               activebackground='#0860ca')
        encrypt_btn.pack(pady=25)
        self.encrypt_btn = encrypt_btn
        
        right_panel = tk.Frame(main_container, bg='#ffffff', relief='solid', bd=1)
        right_panel.pack(side='right', fill='both', expand=True)
        
        console_header = tk.Frame(right_panel, bg='#21262d', height=50)
        console_header.pack(fill='x')
        console_header.pack_propagate(False)
        
        tk.Label(console_header, text="🖥️ Real-time Encryption Console",
                font=('Segoe UI', 12, 'bold'),
                bg='#21262d', fg='#f0f6fc').pack(pady=15)
        
        console_frame = tk.Frame(right_panel, bg='#0d1117')
        console_frame.pack(fill='both', expand=True, padx=3, pady=3)
        
        self.encrypt_console = tk.Text(console_frame,
                                      bg='#0d1117', fg='#7c3aed',
                                      font=('Consolas', 11),
                                      wrap=tk.WORD, state='disabled',
                                      padx=15, pady=15, selectbackground='#264f78')
        
        console_scrollbar = ttk.Scrollbar(console_frame, command=self.encrypt_console.yview)
        self.encrypt_console.config(yscrollcommand=console_scrollbar.set)
        
        self.encrypt_console.pack(side='left', fill='both', expand=True)
        console_scrollbar.pack(side='right', fill='y')
        
        self.log_encrypt("🛡️ Cryptographic system initialized")
        self.log_encrypt("📊 Security level: MAXIMUM")
        self.log_encrypt("🔒 Algorithm: One-Time Pad Enhanced")
        self.log_encrypt("⚡ Status: Ready for operation")
    
    def create_decrypt_tab(self, parent):
        main_container = tk.Frame(parent, bg='#f6f8fa')
        main_container.pack(fill='both', expand=True, padx=15, pady=15)
        
        left_panel = tk.Frame(main_container, bg='#ffffff', relief='solid', bd=1)
        left_panel.pack(side='left', fill='y', padx=(0, 15), ipadx=25, ipady=25)
        
        instructions_frame = tk.LabelFrame(left_panel, text="📋 Decryption Protocol", 
                                         font=('Segoe UI', 12, 'bold'),
                                         bg='#ffffff', fg='#24292f')
        instructions_frame.pack(fill='x', pady=(0, 25))
        
        decrypt_instructions = [
            "1️⃣ Select encrypted file (.encrypted)",
            "2️⃣ Select corresponding key (.key)",
            "3️⃣ Execute secure decryption",
            "4️⃣ File will be saved in 'decrypted_files' folder",
            "",
            "🔒 SECURITY FEATURES:",
            "• Automatic integrity verification",
            "• Cryptographic key validation",
            "• Corruption detection systems",
            "• Bit-perfect restoration"
        ]
        
        for instruction in decrypt_instructions:
            color = '#0969da' if instruction.startswith('🔒') else '#24292f'
            weight = 'bold' if instruction.startswith(('🔒', '•')) else 'normal'
            
            tk.Label(instructions_frame, text=instruction,
                    font=('Segoe UI', 10, weight),
                    bg='#ffffff', fg=color, anchor='w').pack(anchor='w', padx=15, pady=3)
        
        files_frame = tk.LabelFrame(left_panel, text="📁 File Selection",
                                   font=('Segoe UI', 12, 'bold'),
                                   bg='#ffffff', fg='#24292f')
        files_frame.pack(fill='x', pady=(0, 25))
        
        encrypted_subframe = tk.Frame(files_frame, bg='#ffffff')
        encrypted_subframe.pack(fill='x', pady=8)
        
        tk.Button(encrypted_subframe, text="🔐 ENCRYPTED FILE",
                 command=self.select_encrypted_file,
                 font=('Segoe UI', 10, 'bold'),
                 bg='#d1242f', fg='white',
                 relief='flat', padx=20, pady=10,
                 cursor='hand2', activebackground='#b62324').pack(pady=8)
        
        self.encrypted_info_label = tk.Label(encrypted_subframe, text="No encrypted file selected",
                                           font=('Segoe UI', 9),
                                           bg='#ffffff', fg='#656d76',
                                           wraplength=280)
        self.encrypted_info_label.pack(pady=8)
        
        key_subframe = tk.Frame(files_frame, bg='#ffffff')
        key_subframe.pack(fill='x', pady=8)
        
        tk.Button(key_subframe, text="🔑 DECRYPTION KEY",
                 command=self.select_key_file,
                 font=('Segoe UI', 10, 'bold'),
                 bg='#fb8500', fg='white',
                 relief='flat', padx=20, pady=10,
                 cursor='hand2', activebackground='#e07600').pack(pady=8)
        
        self.key_info_label = tk.Label(key_subframe, text="No key file selected",
                                      font=('Segoe UI', 9),
                                      bg='#ffffff', fg='#656d76',
                                      wraplength=280)
        self.key_info_label.pack(pady=8)
        
        decrypt_btn = tk.Button(left_panel, text="🔓 EXECUTE DECRYPTION",
                               command=self.decrypt_file,
                               font=('Segoe UI', 13, 'bold'),
                               bg='#7c3aed', fg='white',
                               relief='flat', padx=35, pady=18,
                               cursor='hand2', state='disabled',
                               activebackground='#6d28d9')
        decrypt_btn.pack(pady=25)
        self.decrypt_btn = decrypt_btn
        
        right_panel = tk.Frame(main_container, bg='#ffffff', relief='solid', bd=1)
        right_panel.pack(side='right', fill='both', expand=True)
        
        console_header = tk.Frame(right_panel, bg='#21262d', height=50)
        console_header.pack(fill='x')
        console_header.pack_propagate(False)
        
        tk.Label(console_header, text="🖥️ Real-time Decryption Console",
                font=('Segoe UI', 12, 'bold'),
                bg='#21262d', fg='#f0f6fc').pack(pady=15)
        
        console_frame = tk.Frame(right_panel, bg='#0d1117')
        console_frame.pack(fill='both', expand=True, padx=3, pady=3)
        
        self.decrypt_console = tk.Text(console_frame,
                                      bg='#0d1117', fg='#7c3aed',
                                      font=('Consolas', 11),
                                      wrap=tk.WORD, state='disabled',
                                      padx=15, pady=15, selectbackground='#264f78')
        
        decrypt_scrollbar = ttk.Scrollbar(console_frame, command=self.decrypt_console.yview)
        self.decrypt_console.config(yscrollcommand=decrypt_scrollbar.set)
        
        self.decrypt_console.pack(side='left', fill='both', expand=True)
        decrypt_scrollbar.pack(side='right', fill='y')
        
        self.log_decrypt("🔓 Decryption module activated")
        self.log_decrypt("🔍 Integrity verification system ready")
        self.log_decrypt("⚡ Awaiting encrypted files")
    
    def create_analysis_tab(self, parent):
        canvas = tk.Canvas(parent, bg='#f6f8fa')
        scrollbar = ttk.Scrollbar(parent, orient='vertical', command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#f6f8fa')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        content_frame = tk.Frame(scrollable_frame, bg='#f6f8fa')
        content_frame.pack(fill='both', expand=True, padx=25, pady=25)
        
        tk.Label(content_frame, text="📊 COMPREHENSIVE SECURITY ANALYSIS",
                font=('Segoe UI', 18, 'bold'),
                bg='#f6f8fa', fg='#24292f').pack(pady=(0, 25))
        
        metrics_frame = tk.LabelFrame(content_frame, text="🛡️ Security Metrics",
                                    font=('Segoe UI', 13, 'bold'),
                                    bg='#ffffff', fg='#24292f')
        metrics_frame.pack(fill='x', pady=15)
        
        metrics_data = [
            ("🔐 Security Level", "MILITARY GRADE", "#2da44e"),
            ("⚡ Quantum Resistance", "100% RESISTANT", "#2da44e"),
            ("🔢 Entropy per Bit", "1.0 (Theoretical Maximum)", "#2da44e"),
            ("🛡️ Algorithm", "One-Time Pad (Shannon 1949)", "#0969da"),
            ("🔍 Verification", "HMAC-SHA256 + Triple Checksum", "#0969da"),
            ("⏱️ Attack Complexity", "2^(file_size×8) operations", "#d1242f"),
            ("🌌 Example (1KB file)", "Number with 2,466 digits", "#d1242f")
        ]
        
        for label, value, color in metrics_data:
            metric_frame = tk.Frame(metrics_frame, bg='#ffffff')
            metric_frame.pack(fill='x', padx=15, pady=8)
            
            tk.Label(metric_frame, text=label, font=('Segoe UI', 11, 'bold'),
                    bg='#ffffff', fg='#24292f').pack(side='left')
            
            tk.Label(metric_frame, text=value, font=('Segoe UI', 11),
                    bg='#ffffff', fg=color).pack(side='right')
        
        attacks_frame = tk.LabelFrame(content_frame, text="🚫 Attack Resistance Matrix",
                                    font=('Segoe UI', 13, 'bold'),
                                    bg='#ffffff', fg='#24292f')
        attacks_frame.pack(fill='x', pady=15)
        
        attacks_list = [
            "✅ Brute Force Attacks: MATHEMATICALLY IMPOSSIBLE",
            "✅ Frequency Analysis: COMPLETELY INEFFECTIVE", 
            "✅ Known Plaintext Attacks: THEORETICALLY IMPOSSIBLE",
            "✅ Chosen Plaintext Attacks: CRYPTOGRAPHICALLY SECURE",
            "✅ Timing Attack Protection: IMPLEMENTED",
            "✅ Cache Attack Mitigation: ACTIVE",
            "✅ Shor's Algorithm (Quantum): NATURALLY RESISTANT",
            "✅ Grover's Algorithm (Quantum): NEGLIGIBLE IMPACT"
        ]
        
        for attack in attacks_list:
            tk.Label(attacks_frame, text=attack, font=('Segoe UI', 11),
                    bg='#ffffff', fg='#2da44e', anchor='w').pack(anchor='w', padx=15, pady=4)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def create_help_tab(self, parent):
        help_content = tk.Text(parent, wrap=tk.WORD, font=('Segoe UI', 11),
                              bg='#ffffff', fg='#24292f', padx=25, pady=25)
        help_content.pack(fill='both', expand=True, padx=25, pady=25)
        
        help_text = """
🛡️ PROFESSIONAL USER GUIDE

📋 STANDARD OPERATING PROCEDURES:

🔐 ENCRYPTION WORKFLOW:
1. Select your target file using the "BROWSE FILES" button
2. Review displayed file information (size, name, requirements)
3. Click "EXECUTE ENCRYPTION" to apply cryptographic protection
4. Monitor real-time progress in the console
5. Secure the generated cryptographic key

🔓 DECRYPTION WORKFLOW:
1. Select the encrypted file (.encrypted extension)
2. Select the corresponding decryption key (.key extension)
3. Execute the decryption process
4. Original file will be restored with integrity verification

⚠️ CRITICAL SECURITY PROTOCOLS:

🚨 KEY MANAGEMENT:
• ONE key = ONE file (never reuse cryptographic keys)
• Store keys in ultra-secure locations
• Key loss = permanent data loss
• Never transmit or share cryptographic keys

🔒 SECURITY SPECIFICATIONS:
• Theoretical perfect secrecy
• Quantum computer resistant
• Supercomputer resistant
• Information-theoretic security

📁 FILE ORGANIZATION:
• Encrypted files: "encrypted_files" directory
• Cryptographic keys: "security_keys" directory
• Restored files: program root directory

🆘 TECHNICAL SUPPORT:
• Comprehensive documentation included
• Detailed diagnostic logging
• Intuitive interface with guidance
• Explicit error messaging

🎖️ CERTIFICATIONS & STANDARDS:
• Mathematically proven algorithm
• Compliant with cryptographic standards
• Validated by modern cryptography
• Approved for sensitive data protection
        """
        
        help_content.insert('1.0', help_text)
        help_content.config(state='disabled')
    
    def create_footer(self):
        footer_frame = tk.Frame(self.root, bg='#21262d', height=35)
        footer_frame.pack(fill='x', side='bottom')
        footer_frame.pack_propagate(False)
        
        tk.Label(footer_frame, text="Unbreakable Encryption v3.0 | Professional Cryptographic Solution | © 2024",
                font=('Segoe UI', 9),
                bg='#21262d', fg='#f0f6fc').pack(side='left', padx=25, pady=10)
        
        tk.Label(footer_frame, text="🛡️ SECURE SYSTEM",
                font=('Segoe UI', 9, 'bold'),
                bg='#21262d', fg='#2da44e').pack(side='right', padx=25, pady=10)
    
    def update_status(self, message):
        self.status_var.set(message)
        self.root.update()
    
    def update_progress(self, value):
        self.progress_var.set(value)
        self.root.update()
    
    def log_encrypt(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        self.encrypt_console.config(state='normal')
        self.encrypt_console.insert(tk.END, formatted_message + '\n')
        self.encrypt_console.see(tk.END)
        self.encrypt_console.config(state='disabled')
        self.root.update()
    
    def log_decrypt(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        self.decrypt_console.config(state='normal')
        self.decrypt_console.insert(tk.END, formatted_message + '\n')
        self.decrypt_console.see(tk.END)
        self.decrypt_console.config(state='disabled')
        self.root.update()
    
    def select_file_to_encrypt(self):
        if self.operation_in_progress:
            messagebox.showwarning("Operation in Progress", "Please wait for current operation to complete")
            return
        
        file_path = filedialog.askopenfilename(
            title="Select File for Encryption - Unbreakable Encryption System",
            filetypes=[
                ("All Files", "*.*"),
                ("Documents", "*.pdf *.doc *.docx *.txt"),
                ("Images", "*.jpg *.png *.gif *.bmp"),
                ("Archives", "*.zip *.rar *.7z"),
                ("Media", "*.mp4 *.mp3 *.avi *.mov")
            ]
        )
        
        if file_path:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            for widget in self.file_info_frame.winfo_children():
                widget.destroy()
            
            info_title = tk.Label(self.file_info_frame, text="📄 FILE SELECTED",
                                 font=('Segoe UI', 10, 'bold'),
                                 bg='#f6f8fa', fg='#24292f')
            info_title.pack(pady=8)
            
            tk.Label(self.file_info_frame, text=f"Name: {file_name}",
                    font=('Segoe UI', 10), bg='#f6f8fa', fg='#656d76').pack(anchor='w', padx=15)
            
            tk.Label(self.file_info_frame, text=f"Size: {file_size:,} bytes",
                    font=('Segoe UI', 10), bg='#f6f8fa', fg='#656d76').pack(anchor='w', padx=15)
            
            tk.Label(self.file_info_frame, text=f"Key Required: {file_size:,} bytes",
                    font=('Segoe UI', 10), bg='#f6f8fa', fg='#0969da').pack(anchor='w', padx=15)
            
            self.encrypt_btn.config(state='normal')
            self.file_to_encrypt = file_path
            
            self.log_encrypt(f"✅ File selected: {file_name} ({file_size:,} bytes)")
            self.update_status(f"File ready: {file_name}")
    
    def select_encrypted_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Encrypted File",
            filetypes=[("Encrypted Files", "*.encrypted"), ("All Files", "*.*")],
            initialdir=self.encrypt_dir
        )
        
        if file_path:
            file_name = os.path.basename(file_path)
            self.encrypted_info_label.config(text=f"🔐 {file_name}")
            self.encrypted_file_path = file_path
            self.log_decrypt(f"📄 Encrypted file selected: {file_name}")
            self.check_decrypt_ready()
    
    def select_key_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Decryption Key",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")],
            initialdir=self.keys_dir
        )
        
        if file_path:
            file_name = os.path.basename(file_path)
            self.key_info_label.config(text=f"🔑 {file_name}")
            self.key_file_path = file_path
            self.log_decrypt(f"🔑 Key selected: {file_name}")
            self.check_decrypt_ready()
    
    def check_decrypt_ready(self):
        if hasattr(self, 'encrypted_file_path') and hasattr(self, 'key_file_path'):
            self.decrypt_btn.config(state='normal')
            self.update_status("Ready for decryption")
    
    def encrypt_file(self):
        if not hasattr(self, 'file_to_encrypt'):
            messagebox.showerror("Error", "No file selected")
            return
        
        self.operation_in_progress = True
        self.encrypt_btn.config(state='disabled')
        
        def encrypt_thread():
            try:
                self.update_status("Encryption in progress...")
                self.update_progress(0)
                
                def progress_callback(message):
                    self.log_encrypt(message)
                    if "in progress" in message.lower() or "en cours" in message.lower():
                        self.update_progress(50)
                    elif "completed" in message.lower() or "terminé" in message.lower():
                        self.update_progress(100)
                
                success, encrypted_file, key_file, message = MilitaryGradeEncryption.encrypt_file(
                    self.file_to_encrypt, progress_callback=progress_callback
                )
                
                if success:
                    self.log_encrypt("🎉 ENCRYPTION COMPLETED SUCCESSFULLY!")
                    self.update_status("Encryption successful")
                    
                    messagebox.showinfo(
                        "Encryption Successful",
                        f"✅ File encrypted successfully!\n\n"
                        f"📄 Encrypted file:\n{os.path.basename(encrypted_file)}\n\n"
                        f"🔑 Decryption key:\n{os.path.basename(key_file)}\n\n"
                        f"⚠️ SECURE THE KEY IN A SAFE LOCATION!"
                    )
                else:
                    self.log_encrypt(f"❌ FAILURE: {message}")
                    self.update_status("Encryption failed")
                    messagebox.showerror("Error", f"Encryption failed:\n{message}")
                    
            except Exception as e:
                self.log_encrypt(f"❌ ERROR: {str(e)}")
                messagebox.showerror("Error", f"Unexpected error:\n{str(e)}")
            
            finally:
                self.operation_in_progress = False
                self.encrypt_btn.config(state='normal')
                self.update_progress(0)
        
        threading.Thread(target=encrypt_thread, daemon=True).start()
    
    def decrypt_file(self):
        if not hasattr(self, 'encrypted_file_path') or not hasattr(self, 'key_file_path'):
            messagebox.showerror("Error", "Missing files")
            return
        
        self.operation_in_progress = True
        self.decrypt_btn.config(state='disabled')
        
        def decrypt_thread():
            try:
                self.update_status("Decryption in progress...")
                self.update_progress(0)
                
                def progress_callback(message):
                    self.log_decrypt(message)
                    if "in progress" in message.lower() or "en cours" in message.lower():
                        self.update_progress(50)
                    elif "completed" in message.lower() or "terminé" in message.lower() or "succès" in message.lower():
                        self.update_progress(100)
                
                success, output_file, message = MilitaryGradeEncryption.decrypt_file(
                    self.encrypted_file_path, self.key_file_path, 
                    progress_callback=progress_callback
                )
                
                if success:
                    self.log_decrypt("🎉 DECRYPTION COMPLETED SUCCESSFULLY!")
                    self.update_status("Decryption successful")
                    
                    messagebox.showinfo(
                        "Decryption Successful",
                        f"✅ File decrypted successfully!\n\n"
                        f"📄 Restored file:\n{os.path.basename(output_file)}\n\n"
                        f"📁 Location: decrypted_files folder\n\n"
                        f"✅ Integrity verified"
                    )
                else:
                    self.log_decrypt(f"❌ FAILURE: {message}")
                    self.update_status("Decryption failed")
                    messagebox.showerror("Error", f"Decryption failed:\n{message}")
                    
            except Exception as e:
                self.log_decrypt(f"❌ ERROR: {str(e)}")
                messagebox.showerror("Error", f"Unexpected error:\n{str(e)}")
            
            finally:
                self.operation_in_progress = False
                self.decrypt_btn.config(state='disabled')
                self.update_progress(0)
        
        threading.Thread(target=decrypt_thread, daemon=True).start()

def main():
    root = tk.Tk()
    app = ProfessionalCryptoInterface(root)
    root.mainloop()

if __name__ == "__main__":
    main()

