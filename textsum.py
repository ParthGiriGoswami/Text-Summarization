import mysql.connector
import customtkinter as ctk
from transformers import pipeline
from message import CustomMessageBox
import pyperclip
import firebase_admin
from firebase_admin import credentials,db
if not firebase_admin._apps:
    cred = credentials.Certificate('cred.json')  
    firebase_admin.initialize_app(cred, {'databaseURL': "https://projectname.firebaseio.com/"})
users_ref = db.reference('data')
try:
    title_generator = pipeline("text2text-generation", model="t5-small", tokenizer="t5-small")
    summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
except:
    pass
mydb=mysql.connector.connect(host="localhost",user="root",password="parth@123",database="face")
mycursor=mydb.cursor()
class text(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        mycursor.execute("select * from users")
        self.result =mycursor.fetchone()
        self.a=[]
        self.a.append("History")
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self, values=["Dark", "Light"], command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.place(x=1400, y=0)
        self.logout=ctk.CTkButton(self,text="Logout",command=self.logout)
        self.logout.place(x=0,y=0)
        self.my_font2 = ctk.CTkFont(family="times new roman", size=20)
        if self.result is not None:
            for key, value in users_ref.get().items():
                if (value.get('Name') == self.result[1]):
                    self.a.append(value.get('Title'))
            self.welcome=ctk.CTkLabel(self,text=f"Welcome {self.result[0]}",font=self.my_font2)
            self.welcome.place(x=700,y=0)
        self.history = ctk.CTkOptionMenu(self, values=self.a, command=self.History)
        self.history.place(x=0, y=50)
        self.texttitle=ctk.CTkLabel(self,text="Text",font=self.my_font2)
        self.texttitle.place(x=330,y=70)
        self.text=ctk.CTkTextbox(self,width=720,height=650,corner_radius=10, wrap="word")
        self.text.place(x=20,y=100)
        self.sum=ctk.CTkLabel(self,text="Summary",font=self.my_font2)
        self.sum.place(x=1100,y=70)
        self.summary=ctk.CTkTextbox(self,width=720,height=650,corner_radius=10, wrap="word",state="disabled")
        self.summary.place(x=780,y=100)
        self.clear=ctk.CTkButton(self,text="Clear",width=720,command=self.clear)
        self.clear.place(x=20,y=760)
        self.btn=ctk.CTkButton(self,text="Summary",width=720,command=self.summ)
        self.btn.place(x=20,y=760)
        self.title_label = ctk.CTkLabel(self, text="", font=self.my_font2)
        self.title_label.place(x=780, y=860)
    def History(self,historyy:str):
        if (not historyy=="History"):
            for key, value in users_ref.get().items():
                if (value.get('Name') == self.result[1] and value.get('Title')==historyy):
                    self.text.delete(0.0,'end')
                    self.summary.configure(state="normal")
                    self.summary.delete(0.0,'end')
                    self.summary.configure(state="disabled")
                    self.text.insert(0.0,value.get('Text'))
                    self.summary.configure(state="normal")
                    self.summary.insert(0.0,value.get('Summary'))
                    self.summary.configure(state="disabled")
                    self.btn.place_forget()
                    self.select=ctk.CTkButton(self,text="Select All",width=360,command=self.select_all)
                    self.select.place(x=780,y=760)
                    self.copy=ctk.CTkButton(self,text="Copy",width=360,command=self.copy)
                    self.copy.place(x=1140,y=760)
    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)
    def logout(self):
        mycursor.execute("delete from users")
        mydb.commit()
        self.controller.show_frame("mainpage")
    def clear(self):
        self.text.delete(0.0,'end')
        self.summary.configure(state="normal")
        self.summary.delete(0.0,'end')
        self.summary.configure(state="disabled")
        self.btn.place(x=20,y=760)
    def copy(self):
        selected_text = self.summary.get("sel.first", "sel.last")
        pyperclip.copy(selected_text)
        CustomMessageBox(message="Copied Successfully")
    def select_all(self):
        self.summary.configure(state="normal")
        self.summary.tag_add("sel", "1.0", "end")
        self.summary.configure(state="disabled")
    def summ(self):
        if(self.text.get(0.0,'end').strip()==""):
            CustomMessageBox(message="Please enter a paragraph")
        else:
            summary = summarizer(self.text.get(0.0,'end'), max_length=len(self.text.get(0.0,'end').split()), min_length=round((len(self.text.get(0.0,'end').split()))/2), do_sample=False)
            self.btn.place_forget()
            self.summary.configure(state="normal")
            self.summary.insert("0.0", summary[0]['summary_text'])
            self.summary.configure(state="disabled")
            self.select=ctk.CTkButton(self,text="Select All",width=360,command=self.select_all)
            self.select.place(x=780,y=760)
            self.copy=ctk.CTkButton(self,text="Copy",width=360,command=self.copy)
            self.copy.place(x=1140,y=760)
            input_text = self.text.get(0.0, 'end').strip()
            title_input = "summarize: " + input_text
            title = title_generator(title_input, max_length=10, min_length=5, do_sample=False)
            users_ref.push({"Name":self.result[1],"Title":title[0]['generated_text'],"Text":self.text.get(0.0,'end'),"Summary":self.summary.get(0.0,'end')})
            self.a.append(title[0]['generated_text'])
            self.history = ctk.CTkOptionMenu(self, values=self.a, command=self.History)
            self.history.place(x=1250, y=0)