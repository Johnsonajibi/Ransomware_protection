#!/usr/bin/env python3
"""
Simple GUI launcher for folder access with USB token authentication
"""
import tkinter as tk
from tkinter import messagebox, filedialog
import subprocess
import os

class FolderAccessGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 USB Token Folder Access")
        self.root.geometry("500x400")
        
        # Check for USB tokens
        self.tokens_found = self.check_usb_tokens()
        
        self.create_widgets()
    
    def check_usb_tokens(self):
        """Check if USB tokens are present"""
        drives = ['E:', 'F:', 'G:', 'H:']
        for drive in drives:
            if os.path.exists(drive):
                try:
                    files = os.listdir(drive)
                    tokens = [f for f in files if f.startswith('protection_token_')]
                    if tokens:
                        return drive, len(tokens)
                except:
                    continue
        return None, 0
    
    def create_widgets(self):
        # Title
        title = tk.Label(self.root, text="🔐 USB Token Folder Access", 
                        font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Token status
        if self.tokens_found[0]:
            status_text = f"✅ {self.tokens_found[1]} USB tokens found on {self.tokens_found[0]}"
            status_color = "green"
        else:
            status_text = "❌ No USB tokens found"
            status_color = "red"
        
        status_label = tk.Label(self.root, text=status_text, 
                               fg=status_color, font=("Arial", 10))
        status_label.pack(pady=5)
        
        # Instructions
        instructions = tk.Text(self.root, height=8, width=60, wrap=tk.WORD)
        instructions.pack(pady=10, padx=20)
        
        instructions.insert(tk.END, 
"""🔑 How to Access Your Protected Folders:

1. GUI Method (Easiest):
   - Click 'Launch Anti-Ransomware GUI' below
   - Use the Protection tab to unlock folders
   - Files will be accessible while GUI is running

2. Command Line Method:
   - python true_prevention.py --unlock-folder "folder_path"
   - python true_prevention.py --show-protected

3. Emergency Access:
   - Click 'Show Hidden Folders' to reveal protected folders
   - Use 'Temporary Access' for quick file retrieval

⚠️ Security Note: Folders re-lock automatically when system closes""")
        
        instructions.config(state=tk.DISABLED)
        
        # Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=20)
        
        if self.tokens_found[0]:
            gui_btn = tk.Button(button_frame, text="🖥️ Launch Anti-Ransomware GUI",
                               command=self.launch_gui, bg="lightgreen")
            gui_btn.pack(pady=5, fill=tk.X)
            
            show_btn = tk.Button(button_frame, text="👁️ Show Hidden Folders",
                               command=self.show_hidden_folders, bg="lightblue")
            show_btn.pack(pady=5, fill=tk.X)
            
            temp_btn = tk.Button(button_frame, text="⏰ Temporary Access",
                               command=self.temporary_access, bg="lightyellow")
            temp_btn.pack(pady=5, fill=tk.X)
        else:
            error_btn = tk.Button(button_frame, text="🔍 Check for USB Drive",
                                command=self.check_tokens, bg="lightcoral")
            error_btn.pack(pady=5, fill=tk.X)
    
    def launch_gui(self):
        """Launch the main anti-ransomware GUI"""
        try:
            subprocess.Popen(['python', 'true_prevention.py'], 
                           cwd=r'c:\Users\ajibi\Music\Anti-Ransomeware')
            messagebox.showinfo("Success", "Anti-ransomware GUI launched!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch GUI: {e}")
    
    def show_hidden_folders(self):
        """Show all folders including hidden ones"""
        try:
            result = subprocess.run(['cmd', '/c', 'dir', '/A:D', 
                                   r'c:\Users\ajibi\Music\Anti-Ransomeware'],
                                  capture_output=True, text=True)
            
            # Create a new window to show results
            result_window = tk.Toplevel(self.root)
            result_window.title("📂 All Folders (Including Protected)")
            result_window.geometry("600x400")
            
            text_area = tk.Text(result_window, wrap=tk.WORD)
            text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_area.insert(tk.END, result.stdout)
            text_area.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show folders: {e}")
    
    def temporary_access(self):
        """Provide instructions for temporary access"""
        messagebox.showinfo("Temporary Access", 
"""⏰ Temporary Access Instructions:

1. Open Command Prompt as Administrator
2. Run: attrib -H -S "folder_path"
3. Access your files quickly
4. The folder will re-protect automatically

⚠️ This only makes folders visible, not fully unlocked.
For full access, use the main GUI.""")
    
    def check_tokens(self):
        """Re-check for USB tokens"""
        self.tokens_found = self.check_usb_tokens()
        if self.tokens_found[0]:
            messagebox.showinfo("Success", f"Found {self.tokens_found[1]} tokens on {self.tokens_found[0]}!")
            self.root.destroy()
            self.__init__()  # Restart GUI
        else:
            messagebox.showwarning("Not Found", "No USB tokens detected. Please ensure your USB drive is connected.")
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = FolderAccessGUI()
    app.run()
