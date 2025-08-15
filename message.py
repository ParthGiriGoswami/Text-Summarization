import customtkinter as ctk
class CustomMessageBox(ctk.CTkToplevel):
    _instance = None
    def __new__(cls,*args,**kwargs):
        if cls._instance is None:
            cls._instance = super(CustomMessageBox, cls).__new__(cls)
        return cls._instance
    def __init__(self,message):
        if not hasattr(self, 'initialized'):
            super().__init__()
            self.geometry("300x150")
            self.resizable(False, False)
            self.update_idletasks()
            self.title("Error")
            width = self.winfo_width()
            height = self.winfo_height()
            x = (self.winfo_screenwidth() // 2) - (width // 2)
            y = (self.winfo_screenheight() // 2) - (height // 2)
            self.geometry(f"{width}x{height}+{x}+{y}")
            self.attributes("-topmost", True)
            self.focus_force()
            self.message_label = ctk.CTkLabel(self, text=message,wraplength=300)
            self.message_label.pack(pady=20)
            self.ok_button = ctk.CTkButton(self, text="OK", command=self.close)
            self.ok_button.place(x=120,y=80)
            self.initialized = True 
    def close(self):
        self.destroy()
        CustomMessageBox._instance = None