import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading

# -------- BACKEND IMPORTS --------
from analyzer import analyze_password
from hashing import hash_password, md5_hash, sha256_hash
from hashcat_attack import is_hashcat_installed
from logger import log_event, log_attack_start, log_attack_end
from report_generator import ReportGenerator


class PasswordToolGUI:
    def __init__(self, root):
        self.root = root
        root.title("Password Analyzer and Cracking Tool")
        root.geometry("1400x800")
        root.configure(bg="#0a0e1a")

        self.attack_running = False
        self.current_attacker = None

        # ---------------- ENHANCED STYLE ----------------
        style = ttk.Style()
        style.theme_use("clam")
        
        # Button styles
        style.configure("TButton", font=("Segoe UI", 10), padding=10)
        style.map("TButton",
                  background=[("active", "#1e3a8a")],
                  foreground=[("active", "white")])
        
        style.configure("TCheckbutton", 
                       background="#1a1f35", 
                       foreground="#e2e8f0",
                       font=("Segoe UI", 9))
        
        style.configure("TRadiobutton",
                       background="#1a1f35",
                       foreground="#e2e8f0",
                       font=("Segoe UI", 10))

        # ---------------- GRADIENT HEADER ----------------
        header = tk.Frame(root, bg="#0a0e1a", height=90)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Header gradient effect (simulated with frames)
        gradient_frame = tk.Frame(header, bg="#1e293b", height=4)
        gradient_frame.pack(fill="x", side="bottom")

        title_frame = tk.Frame(header, bg="#0a0e1a")
        title_frame.pack(expand=True)

        tk.Label(
            title_frame,
            text="Password Analyzer & Cracking Tool",
            font=("Segoe UI", 24, "bold"),
            fg="#60a5fa",
            bg="#0a0e1a"
        ).pack(pady=(15, 2))

        tk.Label(
            title_frame,
            text="Password Analysis & Cracking",
            font=("Segoe UI", 10),
            fg="#94a3b8",
            bg="#0a0e1a"
        ).pack()

        # ---------------- MAIN CONTAINER ----------------
        main = tk.Frame(root, bg="#0a0e1a")
        main.pack(fill="both", expand=True, padx=25, pady=15)

        # ---------------- LEFT PANEL (ENHANCED) ----------------
        left_container = tk.Frame(main, bg="#0a0e1a", width=360)
        left_container.pack(side="left", fill="y", padx=(0, 15))
        left_container.pack_propagate(False)

        left = tk.Frame(left_container, bg="#111827", relief="flat", bd=0)
        left.pack(fill="both", expand=True)

        # Add subtle border effect
        border_frame = tk.Frame(left, bg="#1e293b", height=2)
        border_frame.pack(fill="x")

        # Padding container (removed scroll, making it simpler)
        left_content = tk.Frame(left, bg="#111827")
        left_content.pack(fill="both", expand=True, padx=15, pady=15)

        # Password Input Section
        self._create_section_header(left_content, "Password Input", "#fbbf24")
        
        input_frame = tk.Frame(left_content, bg="#111827")
        input_frame.pack(fill="x", pady=(4, 6))

        self.password_var = tk.StringVar()
        password_container = tk.Frame(input_frame, bg="#1a1f35", relief="solid", bd=1)
        password_container.pack(fill="x")
        
        self.password_entry = tk.Entry(
            password_container, 
            textvariable=self.password_var,
            show="●", 
            bg="#1a1f35", 
            fg="#e2e8f0",
            insertbackground="#60a5fa", 
            relief="flat",
            font=("Segoe UI", 10),
            bd=0
        )
        self.password_entry.pack(fill="x", padx=8, pady=8)

        self.show_var = tk.BooleanVar()
        show_frame = tk.Frame(input_frame, bg="#111827")
        show_frame.pack(fill="x", pady=(3, 0))
        
        ttk.Checkbutton(
            show_frame, 
            text="Show password",
            variable=self.show_var,
            command=self.toggle_password,
            style="TCheckbutton"
        ).pack(anchor="w")

        # Separator
        tk.Frame(left_content, bg="#1e293b", height=1).pack(fill="x", pady=8)

        # Hash Algorithm Section
        self._create_section_header(left_content, "Hash Algorithm", "#a78bfa")
        
        algo_frame = tk.Frame(left_content, bg="#111827")
        algo_frame.pack(fill="x", pady=(4, 6))

        self.algorithm_var = tk.StringVar(value="md5")

        for text, value in [("MD5", "md5"), ("SHA-256", "sha256")]:
            radio_frame = tk.Frame(algo_frame, bg="#1a1f35", relief="flat")
            radio_frame.pack(fill="x", pady=2)
            
            tk.Radiobutton(
                radio_frame, 
                text=text,
                variable=self.algorithm_var,
                value=value,
                bg="#1a1f35",
                fg="#e2e8f0",
                selectcolor="#2563eb",
                activebackground="#1a1f35",
                activeforeground="white",
                font=("Segoe UI", 9),
                indicatoron=True,
                bd=0,
                padx=8,
                pady=3
            ).pack(anchor="w", fill="x")

        # Separator
        tk.Frame(left_content, bg="#1e293b", height=1).pack(fill="x", pady=8)

        # Analysis Section
        self._create_section_header(left_content, "Analysis", "#34d399")
        self._create_action_button(left_content, "Analyze Password", self.analyze, "#059669", "")

        # Separator
        tk.Frame(left_content, bg="#1e293b", height=1).pack(fill="x", pady=8)

        # Attacks Section
        self._create_section_header(left_content, "Attack Methods", "#f87171")
        
        attacks = [
            ("Dictionary Attack", self.dictionary, "#3b82f6", ""),
            ("Brute Force Attack", self.bruteforce, "#8b5cf6", ""),
            ("Hybrid Attack", self.hybrid, "#ec4899", ""),
            ("Hashcat Attack", self.hashcat, "#f59e0b", "")
        ]
        
        for text, cmd, color, icon in attacks:
            self._create_action_button(left_content, text, cmd, color, icon)

        # Separator
        tk.Frame(left_content, bg="#1e293b", height=1).pack(fill="x", pady=8)

        # Reports Section
        self._create_section_header(left_content, "Reports", "#14b8a6")
        self._create_action_button(left_content, "Generate Report", self.generate_report, "#0d9488", "")

        # ---------------- RIGHT PANEL (CONSOLE) ----------------
        right = tk.Frame(main, bg="#111827", relief="flat", bd=0)
        right.pack(side="right", fill="both", expand=True)

        # Console border
        border_frame = tk.Frame(right, bg="#1e293b", height=2)
        border_frame.pack(fill="x")

        # Console header
        header_r = tk.Frame(right, bg="#111827")
        header_r.pack(fill="x", padx=15, pady=12)

        tk.Label(
            header_r, 
            text="Output Console",
            fg="#60a5fa", 
            bg="#111827",
            font=("Segoe UI", 13, "bold")
        ).pack(side="left")

        clear_btn = tk.Button(
            header_r, 
            text="Clear",
            bg="#dc2626", 
            fg="white",
            command=self.clear,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=15,
            pady=6,
            bd=0,
            cursor="hand2"
        )
        clear_btn.pack(side="right")
        
        # Hover effect for clear button
        clear_btn.bind("<Enter>", lambda e: clear_btn.config(bg="#b91c1c"))
        clear_btn.bind("<Leave>", lambda e: clear_btn.config(bg="#dc2626"))

        # Console output with custom styling
        console_frame = tk.Frame(right, bg="#0a0e1a", relief="solid", bd=1)
        console_frame.pack(fill="both", expand=True, padx=15, pady=(0, 12))

        self.output = scrolledtext.ScrolledText(
            console_frame, 
            bg="#0a0e1a", 
            fg="#22d3ee",
            font=("Consolas", 10),
            wrap="none",  # Changed from "word" to "none" to preserve formatting
            insertbackground="#60a5fa",
            padx=15, 
            pady=15,
            relief="flat",
            bd=0,
            selectbackground="#1e3a8a",
            selectforeground="white"
        )
        self.output.pack(fill="both", expand=True)
        
        # Add horizontal scrollbar for long lines
        h_scroll = tk.Scrollbar(console_frame, orient="horizontal", command=self.output.xview)
        h_scroll.pack(side="bottom", fill="x")
        self.output.config(xscrollcommand=h_scroll.set)

        # Enhanced status bar
        status_container = tk.Frame(right, bg="#1a1f35", relief="flat")
        status_container.pack(fill="x", padx=15, pady=(0, 15))

        tk.Frame(status_container, bg="#2563eb", height=2).pack(fill="x")

        self.status_bar = tk.Label(
            status_container, 
            text="● Ready",
            bg="#1a1f35", 
            fg="#94a3b8",
            anchor="w", 
            padx=15, 
            pady=10,
            font=("Segoe UI", 10)
        )
        self.status_bar.pack(fill="x")

        self.show_welcome()

        self.last_analysis = None
        self.attack_results = []

    # ---------------- HELPER METHODS ----------------
    def _create_section_header(self, parent, text, color):
        """Create a styled section header."""
        header_frame = tk.Frame(parent, bg="#111827")
        header_frame.pack(fill="x", pady=(0, 8))
        
        tk.Label(
            header_frame, 
            text=text,
            fg=color, 
            bg="#111827",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w")
        
        tk.Frame(header_frame, bg=color, height=2, width=40).pack(anchor="w", pady=(4, 0))

    def _create_action_button(self, parent, text, cmd, color, icon=""):
        """Create a styled action button with hover effects."""
        btn_frame = tk.Frame(parent, bg="#111827")
        btn_frame.pack(fill="x", pady=1)
        
        display_text = f"{icon}  {text}" if icon else text
        
        btn = tk.Button(
            btn_frame, 
            text=display_text,
            bg=color, 
            fg="white",
            relief="flat", 
            command=cmd,
            font=("Segoe UI", 9),
            cursor="hand2",
            bd=0,
            padx=10,
            pady=6,
            anchor="w"
        )
        btn.pack(fill="x")
        
        # Hover effects
        def on_enter(e):
            btn.config(bg=self._lighten_color(color))
        
        def on_leave(e):
            btn.config(bg=color)
        
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)

    def _lighten_color(self, hex_color):
        """Lighten a hex color for hover effect."""
        color_map = {
            "#059669": "#10b981",
            "#3b82f6": "#60a5fa",
            "#8b5cf6": "#a78bfa",
            "#ec4899": "#f472b6",
            "#f59e0b": "#fbbf24",
            "#0d9488": "#14b8a6",
            "#dc2626": "#ef4444"
        }
        return color_map.get(hex_color, hex_color)

    def toggle_password(self):
        self.password_entry.config(show="" if self.show_var.get() else "●")

    def write(self, text):
        self.output.insert(tk.END, text)
        self.output.see(tk.END)
        self.root.update_idletasks()
    
    def write_header(self, text, color="#60a5fa"):
        """Write text with specified header color."""
        # Create unique tag for this color
        tag_name = f"header_{color.replace('#', '')}"
        self.output.tag_config(tag_name, foreground=color)
        self.output.insert(tk.END, text, tag_name)
        self.output.see(tk.END)
        self.root.update_idletasks()

    def clear(self):
        self.output.delete("1.0", tk.END)

    def set_status(self, text):
        status_icons = {
            "Ready": "●",
            "Analyzing": "○",
            "complete": "✓",
            "Error": "✗",
            "Running": "○"
        }
        
        icon = "●"
        for key, val in status_icons.items():
            if key.lower() in text.lower():
                icon = val
                break
        
        self.status_bar.config(text=f"{icon} {text}")
        self.root.update_idletasks()

    def show_welcome(self):
        self.clear()
        self.write("╔════════════════════════════════════════════════════════════════════════════════════════════╗\n")
        self.write("║                        Paswword Analyzer & Cracking Tool                                   ║\n")
        self.write("╚════════════════════════════════════════════════════════════════════════════════════════════╝\n\n")
        
        self.write("SYSTEM STATUS:\n")
        self.write("──────────────\n")
        
        if is_hashcat_installed():
            self.write("  Hashcat Engine    : ACTIVE (GPU acceleration available)\n")
        else:
            self.write("  Hashcat Engine    : NOT FOUND (using Python implementation)\n")
        
        self.write("  Analysis Module   : READY\n")
        self.write("  Attack Modules    : LOADED\n")
        self.write("  Report Generator  : READY\n")
        
        self.write("\n───────────────────────────────────────────────────\n")
        self.write("Enter a password and select an operation to begin\n")
        self.write("───────────────────────────────────────────────────\n\n")
        
        # Configure text tag for colored headers
        self.output.tag_config("header", foreground="#60a5fa")

    # ---------------- ANALYSIS ----------------
    def analyze(self):
        self.clear()
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning("Input Required", "Please enter a password to analyze")
            return

        self.set_status("Analyzing password...")

        try:
            result = analyze_password(pwd)
            if len(result) == 4:
                strength, entropy, issues, crackable = result
            else:
                strength, entropy, issues = result
                crackable = True

            self.write("╔════════════════════════════════════════════════════════════════════════════════════════════╗\n")
            self.write_header("║                          PASSWORD ANALYSIS REPORT                                          ║\n", "#34d399")
            self.write("╚════════════════════════════════════════════════════════════════════════════════════════════╝\n\n")

            # Strength indicator with color coding
            strength_colors = {
                "Very Weak": "🔴",
                "Weak": "🟠",
                "Moderate": "🟡",
                "Strong": "🟢",
                "Very Strong": "🔵"
            }
            
            indicator = strength_colors.get(strength, "[ ]")
            
            self.write(f"STRENGTH ASSESSMENT:\n")
            self.write("──────────────────────\n")
            self.write(f"  {indicator} Overall Strength : {strength}\n")
            self.write(f"      Entropy          : {entropy:.2f} bits\n")
            self.write(f"      Length           : {len(pwd)} characters\n")
            self.write(f"      Crackable        : {'Yes - Vulnerable' if crackable else 'No - Highly Secure'}\n\n")

            if issues:
                self.write("SECURITY VULNERABILITIES:\n")
                self.write("─────────────────────────\n")
                for i, issue in enumerate(issues, 1):
                    self.write(f"  {i}. {issue}\n")
                self.write("\n")

            self.write("HASH REPRESENTATIONS:\n")
            self.write("─────────────────────\n")
            self.write(f"  MD5        : {md5_hash(pwd)}\n")
            self.write(f"  SHA-256    : {sha256_hash(pwd)}\n")
            self.write(f"  Selected   : {hash_password(pwd, self.algorithm_var.get())} ({self.algorithm_var.get().upper()})\n")

            self.write("\n══════════════════════════════════\n")
            self.write("Analysis completed successfully\n")
            self.write("════════════════════════════════════\n")

            self.last_analysis = {
                "password": pwd,
                "strength": strength,
                "entropy": entropy,
                "issues": issues,
                "is_crackable": crackable
            }

            self.attack_results = []
            log_event(f"Password analyzed - {strength}")
            self.set_status("Analysis complete")

        except Exception as e:
            self.write(f"\n❌ ERROR: Analysis failed\n")
            self.write(f"   Details: {str(e)}\n")
            self.set_status("Error occurred")

    # ---------------- ATTACKS ----------------
    def dictionary(self):
        from cracker_dictionary import DictionaryAttack
        self._run_attack(DictionaryAttack(), "Dictionary Attack", "#3b82f6")

    def bruteforce(self):
        pwd = self.password_var.get()
        if len(pwd) > 5:
            if not messagebox.askyesno("Warning", 
                f"Password length: {len(pwd)} characters\n\n"
                f"Brute force attacks on longer passwords may take significant time.\n\n"
                f"Continue anyway?"):
                return
        
        from cracker_bruteforce import BruteForceAttack
        self._run_attack(BruteForceAttack(), "Brute Force Attack", "#8b5cf6", max_length=len(pwd))

    def hybrid(self):
        from hybrid_attack import HybridAttack
        self._run_attack(HybridAttack(), "Hybrid Attack", "#ec4899")

    def hashcat(self):
        from hashcat_attack import HashcatAttack
        pwd = self.password_var.get()
        self._run_attack(HashcatAttack(), "Hashcat Attack", "#f59e0b", max_length=len(pwd), attack_mode="mask")

    def _run_attack(self, attacker, name, color, **kwargs):
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning("Input Required", "Please enter a password first")
            return

        def run():
            try:
                self.clear()
                self.write("╔════════════════════════════════════════════════════════════════════════════════════════════╗\n")
                self.write_header(f"║ {name.upper():^90} ║\n", color)
                self.write("╚════════════════════════════════════════════════════════════════════════════════════════════╝\n\n")
                
                self.write(f"CONFIGURATION:\n")
                self.write("───────────────\n")
                self.write(f"  Algorithm : {self.algorithm_var.get().upper()}\n")
                self.write(f"  Mode      : Educational (hash then crack)\n")
                self.write(f"  Target    : {len(pwd)} character password\n\n")
                
                self.set_status(f"Running {name}...")
                log_attack_start(name, "educational", self.algorithm_var.get())
                
                result = attacker.attack(
                    target_hash=None,
                    plaintext_password=pwd,
                    algorithm=self.algorithm_var.get(),
                    **kwargs
                )
                
                self.display_result(result)
                self.attack_results.append(result)
                
                log_attack_end(
                    name, 
                    result.get('success', False),
                    result.get('password'),
                    result.get('attempts', 0),
                    result.get('time_seconds', 0),
                    result.get('hash_rate', 0)
                )
                
                self.set_status("Attack complete")
                
            except Exception as e:
                self.write(f"\n❌ {name} FAILED\n")
                self.write(f"   Error: {str(e)}\n")
                self.set_status("Error occurred")

        threading.Thread(target=run, daemon=True).start()

    def display_result(self, result):
        """Display attack result in formatted way."""
        if not result:
            self.write("❌ No result returned\n")
            return
        
        self.write("\n════════════════\n")
        self.write("ATTACK RESULTS:\n")
        self.write("════════════════\n\n")
        
        if result.get('success'):
            self.write("STATUS: SUCCESS\n\n")
            self.write(f"  Cracked Password  : {result.get('password', 'N/A')}\n")
            
            if 'original_password' in result:
                match = result['password'] == result['original_password']
                self.write(f"  Verification      : {'MATCH' if match else 'MISMATCH'}\n")
            
            if 'base_word' in result:
                self.write(f"  Base Word         : {result['base_word']}\n")
            
            if 'transformation' in result:
                self.write(f"  Transformation    : {result['transformation']}\n")
            
            if 'generated_hash' in result:
                hash_display = result['generated_hash'][:64] + "..." if len(result['generated_hash']) > 64 else result['generated_hash']
                self.write(f"  Generated Hash    : {hash_display}\n")
        
        else:
            self.write("STATUS: FAILED\n\n")
            
            if 'error' in result:
                self.write(f"  Error: {result['error']}\n")
            
            if 'message' in result:
                self.write(f"  Info: {result['message']}\n")
            
            if result.get('hashcat_available') == False:
                self.write(f"\n  {result.get('message', '')}\n")
                self.write(f"  Alternative: {result.get('alternative', '')}\n")
        
        self.write("\nPERFORMANCE METRICS:\n")
        self.write("──────────────────────\n")
        
        if 'attempts' in result:
            self.write(f"  Attempts      : {result['attempts']:,}\n")
        
        if 'time_seconds' in result:
            self.write(f"  Time Elapsed  : {result['time_seconds']:.2f} seconds\n")
        
        if 'hash_rate' in result and result['hash_rate'] > 0:
            self.write(f"  Hash Rate     : {result['hash_rate']:,.0f} hashes/sec\n")
        
        if 'hash_algorithm' in result:
            self.write(f"  Algorithm     : {result['hash_algorithm'].upper()}\n")
        
        self.write("\n═════════════════════════\n")
        self.write("Attack sequence completed\n")
        self.write("═════════════════════════\n")

    def generate_report(self):
        """Generate comprehensive report."""
        if not self.last_analysis:
            messagebox.showinfo("No Data", "Please analyze a password before generating a report")
            return
        
        try:
            generator = ReportGenerator()
            
            # Enhanced format selection dialog
            format_window = tk.Toplevel(self.root)
            format_window.title("Generate Report")
            format_window.geometry("380x340")
            format_window.configure(bg="#111827")
            format_window.grab_set()
            format_window.transient(self.root)
            
            # Center window
            format_window.update_idletasks()
            x = (format_window.winfo_screenwidth() // 2) - (380 // 2)
            y = (format_window.winfo_screenheight() // 2) - (340 // 2)
            format_window.geometry(f"380x340+{x}+{y}")
            
            tk.Label(
                format_window, 
                text="Select Report Format",
                bg="#111827", 
                fg="#60a5fa", 
                font=("Segoe UI", 14, "bold")
            ).pack(pady=20)
            
            format_var = tk.StringVar(value="html")
            
            formats = [
                ("txt", "Plain Text", "Simple text format"),
                ("html", "HTML", "Interactive web page"),
                ("json", "JSON", "Structured data"),
                ("md", "Markdown", "Formatted document")
            ]
            
            for fmt, label, desc in formats:
                frame = tk.Frame(format_window, bg="#1a1f35", relief="flat")
                frame.pack(fill="x", padx=30, pady=3)
                
                rb = tk.Radiobutton(
                    frame, 
                    text=f"{label}  •  {desc}",
                    variable=format_var, 
                    value=fmt,
                    bg="#1a1f35", 
                    fg="#e2e8f0",
                    selectcolor="#2563eb",
                    activebackground="#1a1f35",
                    font=("Segoe UI", 9),
                    padx=10,
                    pady=6
                )
                rb.pack(anchor="w", fill="x")
            
            def generate():
                try:
                    filepath = generator.generate_full_report(
                        password=self.last_analysis['password'],
                        strength=self.last_analysis['strength'],
                        entropy=self.last_analysis['entropy'],
                        issues=self.last_analysis['issues'],
                        attack_results=self.attack_results,
                        format=format_var.get()
                    )
                    messagebox.showinfo(
                        "Success", 
                        f"Report generated successfully!\n\nLocation:\n{filepath}"
                    )
                    format_window.destroy()
                except Exception as e:
                    messagebox.showerror("Error", f"Report generation failed:\n\n{str(e)}")
            
            btn_frame = tk.Frame(format_window, bg="#111827")
            btn_frame.pack(pady=18)
            
            gen_btn = tk.Button(
                btn_frame, 
                text="Generate Report",
                command=generate,
                bg="#059669", 
                fg="white",
                font=("Segoe UI", 10, "bold"),
                padx=30,
                pady=10,
                relief="flat",
                cursor="hand2",
                bd=0
            )
            gen_btn.pack()
            
            gen_btn.bind("<Enter>", lambda e: gen_btn.config(bg="#10b981"))
            gen_btn.bind("<Leave>", lambda e: gen_btn.config(bg="#059669"))
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open report dialog:\n\n{str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordToolGUI(root)
    root.mainloop()
