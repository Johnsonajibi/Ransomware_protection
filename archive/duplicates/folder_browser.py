"""
FOLDER BROWSER POPUP - REAL IMPLEMENTATION
Real folder selection interface for production system
"""

import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys
from pathlib import Path
import json
import requests

class RealFolderBrowser:
    def __init__(self):
        self.selected_folder = None
        self.root = None
        
    def show_browser(self):
        """Show real folder browser"""
        self.root = tk.Tk()
        self.root.title("🛡️ Select Folder to Protect")
        self.root.geometry("800x600")
        self.root.configure(bg='#2d3748')
        
        # Main frame
        main_frame = tk.Frame(self.root, bg='#2d3748')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Title
        title_label = tk.Label(main_frame, 
                              text="Select Folder for Anti-Ransomware Protection",
                              font=('Arial', 16, 'bold'),
                              bg='#2d3748', fg='white')
        title_label.pack(pady=(0, 20))
        
        # Path display
        path_frame = tk.Frame(main_frame, bg='#2d3748')
        path_frame.pack(fill='x', pady=(0, 10))
        
        tk.Label(path_frame, text="Current Path:", 
                bg='#2d3748', fg='white').pack(side='left')
        
        self.path_var = tk.StringVar(value="C:\\")
        path_entry = tk.Entry(path_frame, textvariable=self.path_var, 
                             font=('Consolas', 10), width=60)
        path_entry.pack(side='left', padx=(10, 5), fill='x', expand=True)
        
        tk.Button(path_frame, text="📁 Browse", 
                 command=self.browse_path,
                 bg='#4299e1', fg='white').pack(side='right')
        
        # File tree
        tree_frame = tk.Frame(main_frame, bg='#2d3748')
        tree_frame.pack(fill='both', expand=True)
        
        self.tree = ttk.Treeview(tree_frame, columns=('type', 'size'), 
                                show='tree headings', height=15)
        self.tree.heading('#0', text='Name')
        self.tree.heading('type', text='Type')
        self.tree.heading('size', text='Size')
        
        self.tree.column('#0', width=400)
        self.tree.column('type', width=100)
        self.tree.column('size', width=100)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Bind double-click
        self.tree.bind('<Double-1>', self.on_double_click)
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg='#2d3748')
        button_frame.pack(fill='x', pady=(20, 0))
        
        tk.Button(button_frame, text="🆙 Parent Directory", 
                 command=self.go_parent,
                 bg='#718096', fg='white', width=15).pack(side='left')
        
        tk.Button(button_frame, text="🔄 Refresh", 
                 command=self.refresh_tree,
                 bg='#4299e1', fg='white', width=12).pack(side='left', padx=(10, 0))
        
        tk.Button(button_frame, text="✅ Protect This Folder", 
                 command=self.select_folder,
                 bg='#48bb78', fg='white', width=20).pack(side='right')
        
        tk.Button(button_frame, text="❌ Cancel", 
                 command=self.root.destroy,
                 bg='#f56565', fg='white', width=12).pack(side='right', padx=(0, 10))
        
        # Load initial content
        self.load_drives()
        
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (self.root.winfo_width() // 2)
        y = (self.root.winfo_screenheight() // 2) - (self.root.winfo_height() // 2)
        self.root.geometry(f"+{x}+{y}")
        
        self.root.mainloop()
        return self.selected_folder
    
    def load_drives(self):
        """Load available drives"""
        self.tree.delete(*self.tree.get_children())
        
        try:
            # Get Windows drives
            import win32api
            drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
            
            for drive in drives:
                if drive:
                    try:
                        volume_info = win32api.GetVolumeInformation(drive)
                        label = volume_info[0] if volume_info[0] else "Local Disk"
                        display_name = f"{drive} ({label})"
                        
                        self.tree.insert('', 'end', 
                                       values=('Drive', ''),
                                       text=display_name,
                                       tags=(drive,))
                    except:
                        self.tree.insert('', 'end', 
                                       values=('Drive', ''),
                                       text=drive,
                                       tags=(drive,))
        except ImportError:
            # Fallback for non-Windows
            for drive in ['C:\\', 'D:\\', 'E:\\']:
                if os.path.exists(drive):
                    self.tree.insert('', 'end', 
                                   values=('Drive', ''),
                                   text=drive,
                                   tags=(drive,))
    
    def browse_path(self):
        """Browse to specific path"""
        path = self.path_var.get()
        if os.path.exists(path) and os.path.isdir(path):
            self.load_directory(path)
        else:
            messagebox.showerror("Error", f"Path not found: {path}")
    
    def load_directory(self, path):
        """Load directory contents"""
        try:
            self.tree.delete(*self.tree.get_children())
            self.path_var.set(path)
            
            items = []
            
            # Get directory contents with path validation (CWE-22)
            from pathlib import Path
            import logging
            logger = logging.getLogger(__name__)
            
            try:
                # Validate and resolve the path to prevent directory traversal
                resolved_path = os.path.abspath(path)
                # Verify the path is within acceptable directories
                if '..' in Path(path).parts:
                    raise ValueError("Directory traversal attempt detected")
            except (ValueError, RuntimeError) as e:
                logger.error(f"Path validation failed: {type(e).__name__}")
                return
            
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                
                if os.path.isdir(item_path):
                    try:
                        # Check if directory is accessible
                        os.listdir(item_path)
                        items.append({
                            'name': item,
                            'path': item_path,
                            'type': 'Folder',
                            'size': '',
                            'accessible': True
                        })
                    except PermissionError:
                        items.append({
                            'name': f"{item} (Access Denied)",
                            'path': item_path,
                            'type': 'Folder',
                            'size': '',
                            'accessible': False
                        })
                else:
                    try:
                        size = os.path.getsize(item_path)
                        size_str = self.format_size(size)
                        items.append({
                            'name': item,
                            'path': item_path,
                            'type': 'File',
                            'size': size_str,
                            'accessible': True
                        })
                    except:
                        items.append({
                            'name': item,
                            'path': item_path,
                            'type': 'File',
                            'size': 'Unknown',
                            'accessible': True
                        })
            
            # Sort: folders first, then files
            folders = [item for item in items if item['type'] == 'Folder']
            files = [item for item in items if item['type'] == 'File']
            
            folders.sort(key=lambda x: x['name'].lower())
            files.sort(key=lambda x: x['name'].lower())
            
            # Add to tree
            for item in folders + files:
                icon = "📁" if item['type'] == 'Folder' else "📄"
                self.tree.insert('', 'end',
                               values=(item['type'], item['size']),
                               text=f"{icon} {item['name']}",
                               tags=(item['path'], item['accessible']))
                
        except Exception as e:
            messagebox.showerror("Error", f"Cannot load directory: {str(e)}")
    
    def format_size(self, size):
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def on_double_click(self, event):
        """Handle double-click on tree item"""
        item = self.tree.selection()[0]
        tags = self.tree.item(item, 'tags')
        
        if len(tags) >= 2 and tags[1] == 'True':  # Accessible
            path = tags[0]
            if os.path.isdir(path):
                self.load_directory(path)
    
    def go_parent(self):
        """Go to parent directory"""
        current_path = self.path_var.get()
        parent = os.path.dirname(current_path)
        
        if parent != current_path:  # Not root
            self.load_directory(parent)
        else:
            # Go back to drives view
            self.load_drives()
            self.path_var.set("")
    
    def refresh_tree(self):
        """Refresh current directory"""
        current_path = self.path_var.get()
        if current_path and os.path.exists(current_path):
            self.load_directory(current_path)
        else:
            self.load_drives()
    
    def select_folder(self):
        """Select current folder for protection"""
        current_path = self.path_var.get()
        
        if not current_path or not os.path.exists(current_path):
            messagebox.showerror("Error", "Please select a valid folder")
            return
        
        if not os.path.isdir(current_path):
            messagebox.showerror("Error", "Please select a folder, not a file")
            return
        
        # Confirm selection
        result = messagebox.askyesno("Confirm Protection", 
                                   f"Add anti-ransomware protection to:\n\n{current_path}\n\n"
                                   f"This will monitor all files in this folder for threats.")
        
        if result:
            # Send to main system
            try:
                response = requests.post('http://localhost:8080/api/add-folder', 
                                       json={
                                           'path': current_path,
                                           'policy': 'high_security'
                                       },
                                       timeout=10)
                
                if response.json().get('success'):
                    messagebox.showinfo("Success", 
                                      f"Protection added successfully!\n\n"
                                      f"Folder: {current_path}\n"
                                      f"Policy: High Security")
                    self.selected_folder = current_path
                    self.root.destroy()
                else:
                    messagebox.showerror("Error", "Failed to add folder protection")
                    
            except requests.exceptions.ConnectionError:
                messagebox.showerror("Error", 
                                   "Cannot connect to protection system.\n"
                                   "Please ensure the main system is running.")
            except Exception as e:
                messagebox.showerror("Error", f"Error adding protection: {str(e)}")

if __name__ == '__main__':
    browser = RealFolderBrowser()
    selected = browser.show_browser()
    if selected:
        print(f"Selected folder: {selected}")
    else:
        print("No folder selected")
