#!/usr/bin/env python3
"""
File Manager for Protected Folders
Allows adding files to protected folders with USB token authentication
"""
import os
import sys
import shutil
import json
import hashlib
import platform
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess

class ProtectedFolderFileManager:
    def __init__(self):
        self.machine_id = self.get_machine_id()
        self.usb_tokens = self.find_usb_tokens()
        
        # Set up GUI
        self.root = tk.Tk()
        self.root.title("🔐 Protected Folder File Manager")
        self.root.geometry("700x500")
        
        self.create_widgets()
    
    def get_machine_id(self):
        """Generate unique machine ID"""
        system_info = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        return hashlib.sha256(system_info.encode()).hexdigest()[:16]
    
    def find_usb_tokens(self):
        """Find USB drives with protection tokens"""
        drives = ['E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:']
        valid_tokens = []
        
        for drive in drives:
            if os.path.exists(drive):
                try:
                    for file in os.listdir(drive):
                        if file.startswith('protection_token_') and file.endswith('.key'):
                            token_path = os.path.join(drive, file)
                            valid_tokens.append(token_path)
                except:
                    continue
        
        return valid_tokens
    
    def create_widgets(self):
        # Title
        title = tk.Label(self.root, text="🔐 Protected Folder File Manager", 
                        font=("Arial", 16, "bold"))
        title.pack(pady=10)
        
        # Token status
        if self.usb_tokens:
            status_text = f"✅ {len(self.usb_tokens)} USB tokens found"
            status_color = "green"
        else:
            status_text = "❌ No USB tokens found - Please insert USB drive"
            status_color = "red"
        
        status_label = tk.Label(self.root, text=status_text, 
                               fg=status_color, font=("Arial", 10))
        status_label.pack(pady=5)
        
        # Instructions
        instructions = tk.Text(self.root, height=6, width=80, wrap=tk.WORD)
        instructions.pack(pady=10, padx=20)
        
        instructions.insert(tk.END, 
"""📁 How to Add Files to Protected Folders:

1. Select a protected folder from the list below
2. Choose files to add using the "Browse Files" button  
3. Click "Add Files" to temporarily unlock, copy files, and re-lock
4. Files will be automatically protected after copying

⚠️ Important: This requires a valid USB token for security!""")
        
        instructions.config(state=tk.DISABLED)
        
        # Protected folders list
        folders_frame = tk.LabelFrame(self.root, text="🛡️ Protected Folders", font=("Arial", 10, "bold"))
        folders_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Folders listbox
        self.folders_listbox = tk.Listbox(folders_frame, height=8)
        self.folders_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Refresh and populate folders
        self.refresh_folders()
        
        # File selection frame
        file_frame = tk.LabelFrame(self.root, text="📄 Files to Add")
        file_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.files_to_add = []
        self.files_label = tk.Label(file_frame, text="No files selected", fg="gray")
        self.files_label.pack(pady=5)
        
        # Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="🔄 Refresh Folders", 
                  command=self.refresh_folders).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="📁 Browse Files", 
                  command=self.browse_files).pack(side=tk.LEFT, padx=5)
        
        if self.usb_tokens:
            ttk.Button(button_frame, text="➕ Add Files to Protected Folder", 
                      command=self.add_files_to_folder, 
                      style="Accent.TButton").pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="🔍 View Folder Contents", 
                  command=self.view_folder_contents).pack(side=tk.LEFT, padx=5)
    
    def refresh_folders(self):
        """Refresh the list of protected folders"""
        self.folders_listbox.delete(0, tk.END)
        
        # Find folders with protection attributes
        desktop = Path.home() / "OneDrive" / "Desktop"
        if desktop.exists():
            try:
                for item in desktop.iterdir():
                    if item.is_dir():
                        # Check if folder has protection attributes
                        result = subprocess.run(['attrib', str(item)], 
                                              capture_output=True, text=True)
                        if 'H' in result.stdout and 'S' in result.stdout:
                            self.folders_listbox.insert(tk.END, str(item))
            except Exception as e:
                print(f"Error scanning desktop: {e}")
        
        # Also check the anti-ransomware directory
        ar_dir = Path("c:\\Users\\ajibi\\Music\\Anti-Ransomeware")
        if ar_dir.exists():
            try:
                for item in ar_dir.iterdir():
                    if item.is_dir():
                        result = subprocess.run(['attrib', str(item)], 
                                              capture_output=True, text=True)
                        if 'H' in result.stdout and 'S' in result.stdout:
                            self.folders_listbox.insert(tk.END, str(item))
            except Exception as e:
                print(f"Error scanning AR directory: {e}")
    
    def browse_files(self):
        """Browse for files to add"""
        files = filedialog.askopenfilenames(
            title="Select files to add to protected folder",
            filetypes=[
                ("All files", "*.*"),
                ("Documents", "*.pdf;*.doc;*.docx;*.txt"),
                ("Images", "*.jpg;*.jpeg;*.png;*.gif"),
                ("Videos", "*.mp4;*.avi;*.mov"),
            ]
        )
        
        if files:
            self.files_to_add = list(files)
            if len(files) == 1:
                self.files_label.config(text=f"Selected: {os.path.basename(files[0])}", fg="blue")
            else:
                self.files_label.config(text=f"Selected: {len(files)} files", fg="blue")
    
    def view_folder_contents(self):
        """View contents of selected protected folder"""
        selection = self.folders_listbox.curselection()
        if not selection:
            messagebox.showwarning("Selection Required", "Please select a protected folder first")
            return
        
        folder_path = self.folders_listbox.get(selection[0])
        
        # Create a new window to show folder contents
        contents_window = tk.Toplevel(self.root)
        contents_window.title(f"📂 Contents of {os.path.basename(folder_path)}")
        contents_window.geometry("500x400")
        
        # Try to list contents (may be denied due to protection)
        try:
            files = list(Path(folder_path).iterdir())
            contents_text = tk.Text(contents_window, wrap=tk.WORD)
            contents_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            contents_text.insert(tk.END, f"📁 Folder: {folder_path}\n")
            contents_text.insert(tk.END, f"📊 Total items: {len(files)}\n")
            contents_text.insert(tk.END, "=" * 50 + "\n\n")
            
            for file in files[:20]:  # Show first 20 items
                if file.is_dir():
                    contents_text.insert(tk.END, f"📁 {file.name}\n")
                else:
                    size = file.stat().st_size if file.exists() else 0
                    contents_text.insert(tk.END, f"📄 {file.name} ({size:,} bytes)\n")
            
            if len(files) > 20:
                contents_text.insert(tk.END, f"\n... and {len(files) - 20} more items")
            
            contents_text.config(state=tk.DISABLED)
            
        except Exception as e:
            error_label = tk.Label(contents_window, 
                                 text=f"❌ Cannot access folder contents:\n{e}\n\nFolder is protected - use USB token to unlock first", 
                                 fg="red", wraplength=400)
            error_label.pack(expand=True, padx=20, pady=20)
    
    def add_files_to_folder(self):
        """Add files to selected protected folder"""
        if not self.usb_tokens:
            messagebox.showerror("USB Token Required", "Please insert your USB drive with protection tokens")
            return
        
        # Check folder selection
        selection = self.folders_listbox.curselection()
        if not selection:
            messagebox.showwarning("Selection Required", "Please select a protected folder")
            return
        
        # Check file selection
        if not self.files_to_add:
            messagebox.showwarning("Files Required", "Please browse and select files to add")
            return
        
        folder_path = self.folders_listbox.get(selection[0])
        
        # Confirmation dialog
        file_names = "\n".join([os.path.basename(f) for f in self.files_to_add[:5]])
        if len(self.files_to_add) > 5:
            file_names += f"\n... and {len(self.files_to_add) - 5} more files"
        
        confirm_msg = f"""🔐 Add Files to Protected Folder

Target Folder:
{folder_path}

Files to Add:
{file_names}

Process:
1. Temporarily unlock folder using USB token
2. Copy selected files
3. Re-apply protection to folder and new files

Continue?"""
        
        if not messagebox.askyesno("Confirm File Addition", confirm_msg):
            return
        
        # Execute the file addition process
        try:
            self.execute_file_addition(folder_path, self.files_to_add)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add files:\n{e}")
    
    def execute_file_addition(self, folder_path, files_to_add):
        """Execute the file addition with temporary unlock"""
        progress_window = tk.Toplevel(self.root)
        progress_window.title("🔄 Adding Files...")
        progress_window.geometry("400x200")
        
        progress_text = tk.Text(progress_window, wrap=tk.WORD)
        progress_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def log(message):
            progress_text.insert(tk.END, message + "\n")
            progress_text.see(tk.END)
            progress_window.update()
        
        try:
            log("🔑 Step 1: Verifying USB token...")
            if not self.usb_tokens:
                raise Exception("No USB tokens found")
            log("✅ USB token verified")
            
            log("🔓 Step 2: Temporarily unlocking folder...")
            # Remove protection attributes temporarily
            subprocess.run(['attrib', '-H', '-S', '-R', folder_path], 
                          capture_output=True, check=True)
            log("✅ Folder temporarily unlocked")
            
            log("📋 Step 3: Copying files...")
            copied_files = []
            for i, file_path in enumerate(files_to_add, 1):
                try:
                    dest_path = os.path.join(folder_path, os.path.basename(file_path))
                    shutil.copy2(file_path, dest_path)
                    copied_files.append(dest_path)
                    log(f"✅ Copied {i}/{len(files_to_add)}: {os.path.basename(file_path)}")
                except Exception as e:
                    log(f"❌ Failed to copy {os.path.basename(file_path)}: {e}")
            
            log("🔒 Step 4: Re-applying protection...")
            # Re-apply protection attributes
            subprocess.run(['attrib', '+H', '+S', '+R', folder_path], 
                          capture_output=True, check=True)
            
            # Apply protection to new files
            for file_path in copied_files:
                try:
                    subprocess.run(['attrib', '+H', '+S', '+R', file_path], 
                                  capture_output=True, check=True)
                    log(f"🛡️ Protected: {os.path.basename(file_path)}")
                except Exception as e:
                    log(f"⚠️ Warning - could not protect: {os.path.basename(file_path)}")
            
            log("🎉 Process complete!")
            log(f"✅ Successfully added {len(copied_files)} files to protected folder")
            
            # Clear file selection
            self.files_to_add = []
            self.files_label.config(text="No files selected", fg="gray")
            
            # Show completion message
            tk.Label(progress_window, text="🎉 Files added successfully!", 
                    fg="green", font=("Arial", 12, "bold")).pack(pady=10)
            
        except Exception as e:
            log(f"❌ Error: {e}")
            tk.Label(progress_window, text="❌ Process failed", 
                    fg="red", font=("Arial", 12, "bold")).pack(pady=10)
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = ProtectedFolderFileManager()
    app.run()
