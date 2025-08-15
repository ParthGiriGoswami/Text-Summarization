import mysql.connector  
import customtkinter as ctk
from textsum import text  
from login import mainpage
mydb = mysql.connector.connect(host="localhost",user="root",password="parth@123")
mycursor = mydb.cursor()
mycursor.execute("SET GLOBAL event_scheduler = ON")
mycursor.execute("CREATE DATABASE IF NOT EXISTS face")
mycursor.execute("USE face")
mycursor.execute("CREATE TABLE IF NOT EXISTS users(name varchar(100),email_id_or_phone_number VARCHAR(100), password VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
mycursor.execute("CREATE EVENT IF NOT EXISTS delete_old_records ON SCHEDULE EVERY 1 MINUTE STARTS CURRENT_TIMESTAMP DO DELETE FROM users WHERE created_at < (NOW() - INTERVAL 1 DAY)")
mydb.commit()
class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Text Summarization")
        self.after(0, lambda: self.state("zoomed"))
        self.geometry("+0+0")
        self.minsize(1523,780)
        container = ctk.CTkFrame(self)
        container.pack(fill="both", expand=True)
        self.frames = {}
        for FrameClass in (mainpage, text):
            frame = FrameClass(container, self)
            self.frames[FrameClass.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        mycursor.execute("select * from users")
        result =mycursor.fetchone()
        if result is None:
            self.show_frame("mainpage")
        else:
            self.show_frame("text")
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
    def show_frame(self, frame_name):
        frame = self.frames.get(frame_name)
        frame.tkraise()
    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)
if __name__ == "__main__":
    app = MainApp()
    app.mainloop()
mycursor.close()
mydb.close()