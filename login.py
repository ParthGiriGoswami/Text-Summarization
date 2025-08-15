import mysql.connector
import customtkinter as ctk
import re
import random
import smtplib
import firebase_admin
from firebase_admin import credentials,db
from PIL import Image
import phonenumbers
import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from message import CustomMessageBox
regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+') 
pattern = r'^\+(?!0)\d+$'
pattern1="^\+91\d{10}$"
mydb=mysql.connector.connect(host="localhost",user="root",password="parth@123",database="face")
mycursor=mydb.cursor()
if not firebase_admin._apps:
    cred = credentials.Certificate('file.json')  
    firebase_admin.initialize_app(cred, {'databaseURL': "https://project.firebaseio.com/"})
users_ref = db.reference('users')
users_ref1 = db.reference('encryption')
regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
class mainpage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self, values=["Dark", "Light"], command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.place(x=1400, y=0)
        self.loginapp()
    def encryption(self,email, data):
        data_bytes = data.encode('utf-8')
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
        nonce = cipher.nonce
        user_ref1 = None
        for k, value in users_ref1.get().items():
            if value.get("Email Id or phone number") == email:
                user_ref1 = users_ref1.child(k)
                break
        if user_ref1 is None:
            user_ref1 = users_ref1.push()
        user_ref1.set({"Email Id or phone number": email,"key": base64.b64encode(key).decode('utf-8'),"tag": base64.b64encode(tag).decode('utf-8'),"nonce": base64.b64encode(nonce).decode('utf-8')})
        return ciphertext
    def decryption(self,email):
        user_data = None
        for k, value in users_ref.get().items():
            if value.get("Email Id or phone number") == email:
                user_data = value
                break
        user_data1 = None
        for k, value in users_ref1.get().items():
            if value.get("Email Id or phone number") == email:
                user_data1 = value
                break
        try:
            key = base64.b64decode(user_data1.get('key'))
            ciphertext = base64.b64decode(user_data.get('Password'))
            tag = base64.b64decode(user_data1.get('tag'))
            nonce = base64.b64decode(user_data1.get('nonce'))
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            print(f'Error during decryption: {e}')
            return False
    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)
    def verify1(self):
        if(self.email1.get().strip()=="" or self.passwd1.get().strip()==""):
            CustomMessageBox(message="All fields are required")
        else:
            try:
                flag=0
                for key, value in users_ref.get().items():
                    if value.get('Email Id or phone number') == self.email1.get().lower().strip():
                        name=value.get('Name')
                        flag=1
                        passwd= self.decryption(self.email1.get().lower().strip())
                        if self.passwd1.get().strip()==passwd:
                            flag=2
                            break
                if(flag==2):
                    if(self.check_var.get()=="on"):
                        mycursor.execute("insert into users (name,email_id_or_phone_number,password) values(%s,%s,%s)",(name,self.email1.get(),self.passwd1.get()))
                        mydb.commit()
                    self.email1.delete(0,"end")
                    self.passwd1.delete(0,"end")
                    self.email1.focus_set()
                    self.controller.show_frame("text")
                elif(flag==1):
                    CustomMessageBox(message="Please enter correct password")
                else:
                    CustomMessageBox(message="Unregistered email id or phone number")   
                    self.email1.delete(0,"end")
                    self.passwd1.delete(0,"end")
                    self.email1.focus_set()
            except:
                CustomMessageBox(message="Please check your internet connection")
    def verify2(self):
        if(self.passwd.get().strip()==" " or self.conpasswd.get().strip()==" "):
            CustomMessageBox(message="Fill all fields")
        elif(self.passwd.get().strip()!=self.conpasswd.get().strip()):
            CustomMessageBox(message="Password and confirm password must be same")
        else:
            for key, value in users_ref.get().items():
                if value.get('Email Id or phone number') == self.evar.get().lower().strip():
                    user_ref=users_ref.child(key)
                    passwd=self.encryption(self.evar.get().lower().strip(),self.passwd.get().strip())
                    user_ref.update({"Password":base64.b64encode(passwd).decode('utf-8')})
                    self.loginapp()
    def verifyotp(self):
        if(not self.evar2.get().strip()==" "):
            if(self.maxattempts!=3):
                if(self.evar2.get().strip()==str(self.otp)):
                    self.frame1=ctk.CTkFrame(self,width=850,height=600)
                    self.frame1.place(x=350,y=100)
                    self.back=ctk.CTkButton(self.frame1,text="Back",width=850,height=50,font=self.my_font,command=self.forget)
                    self.back.place(x=0,y=0)
                    self.my_font1 = ctk.CTkFont(family="times new roman", size=40)
                    self.my_font2 = ctk.CTkFont(family="times new roman", size=20)
                    self.title=ctk.CTkLabel(self.frame1,text="Forgot Password",font=self.my_font1)
                    self.title.place(x=310,y=150)
                    self.passwd=ctk.CTkEntry(self.frame1,placeholder_text="Enter new password",width=450,show="*")
                    self.passwd.place(x=40,y=200)
                    self.passwd.focus_set()
                    self.conpasswd=ctk.CTkEntry(self.frame1,placeholder_text="Confirm new password",width=450,show="*")
                    self.conpasswd.place(x=40,y=250)
                    self.v=ctk.CTkButton(self.frame1, text="Verify",command=self.verify2,width=50)
                    self.v.place(x=40,y=300)
                else:
                    self.evar2.delete(0,"end")
                    self.evar2.focus_set()
                    CustomMessageBox(message="Incorrect otp")
            else:
                self.loginapp()
    def sendemail(self,email):
        flag=False
        try:
            s = smtplib.SMTP("smtp.gmail.com", 587)  
            s.starttls()
            s.login("s9174213@gmail.com", "ojwneohzsklvsmbl")
            self.otp = random.randint(1000, 9999)
            msg="Your otp is "+str(self.otp)
            s.sendmail("s9174213@gmail.com",email,msg)
            flag=True
        finally:
            return flag
    def sendsms(self,number):
        flag=False
        try:
            api_key = 'c688b3f2-0553-11ef-8cbb-0200cd936042'
            self.otp = random.randint(1000, 9999)
            sms_url = f'https://2factor.in/API/V1/{api_key}/SMS/{str(number)}/{self.otp}/otp1'
            response = requests.get(sms_url)
            if response.status_code != 200:
                CustomMessageBox(message=f'{response.json()["Details"]}')
            else:
                flag=True
        finally:
            return flag
    def forgetotpframe(self):
        self.frame1=ctk.CTkFrame(self,width=850,height=600)
        self.frame1.place(x=350,y=100)
        self.back=ctk.CTkButton(self.frame1,text="Back",width=850,height=50,font=self.my_font,command=self.forget)
        self.back.place(x=0,y=0)
        self.my_font1 = ctk.CTkFont(family="times new roman", size=40)
        self.my_font2 = ctk.CTkFont(family="times new roman", size=20)
        self.title=ctk.CTkLabel(self.frame1,text="Forgot Password",font=self.my_font1)
        self.title.place(x=310,y=150)
        self.entry=ctk.CTkLabel(self.frame1,text="Enter the 4 digit otp",font=self.my_font)
        self.entry.place(x=40,y=260)
        self.evar2=ctk.CTkEntry(self.frame1,placeholder_text="OTP", width=550,height=50,font=self.my_font2)
        self.evar2.place(x=30,y=350)
        self.evar2.focus_set()
        self.var=ctk.CTkButton(self.frame1,text="Verify",width=200,height=50,font=self.my_font,command=self.verifyotp)
        self.var.place(x=610,y=350)
    def otpvar(self):
        if(self.evar.get().strip()==" "):
            CustomMessageBox(self, message="All fields are required")
        elif(re.match(pattern,self.evar.get().strip())):
            if(re.match(pattern1,self.evar.get().strip())):
                flag=0
                for key, value in users_ref.get().items():
                    if value.get('Email Id or phone number') == self.evar.get().lower():
                        flag=1
                        break
                if(flag==1):
                    try:
                        phone_number = phonenumbers.parse(self.evar.get().strip())
                        if phonenumbers.is_valid_number(phone_number) and phonenumbers.is_possible_number(phone_number):
                            if(self.sendsms(self.evar.get().strip())==True):
                                self.forgetotpframe()
                        else:
                            CustomMessageBox(message="Invalid phone number")
                    except Exception as e:
                        CustomMessageBox(message=e)
                else:
                    self.evar.delete(0,"end")
                    self.evar.focus_set()
                    CustomMessageBox(message="This email id or phone number is unregustered")
        elif(not re.fullmatch(regex,self.evar.get().strip().lower())):
            CustomMessageBox(message="Invalid Email Id")
        elif(self.evar.get().strip().lower().find(" ")!=-1):
            CustomMessageBox(message="Invalid Email Id")
        else:
            try:
                flag=0
                for key, value in users_ref.get().items():
                    if value.get('Email Id or phone number') == self.evar.get().lower().strip():
                        flag=1
                        break
                if(flag==1):
                    if(self.sendemail(self.evar.get().strip().lower())==True):
                        self.forgetotpframe()
                    else:
                        CustomMessageBox(message="Check your internet connection")
                else:
                    self.evar.delete(0,"end")
                    self.evar.focus_set()
                    CustomMessageBox(message="This email id or phone number is unregustered")
            except:
                CustomMessageBox(message="Check your internet connection")
    def forget(self):
        self.maxattempts=0
        self.frame1=ctk.CTkFrame(self,width=850,height=600)
        self.frame1.place(x=350,y=100)
        self.back=ctk.CTkButton(self.frame1,text="Back",width=850,height=50,font=self.my_font,command=self.loginapp)
        self.back.place(x=0,y=0)
        self.my_font1 = ctk.CTkFont(family="times new roman", size=40)
        self.my_font2 = ctk.CTkFont(family="times new roman", size=20)
        self.title=ctk.CTkLabel(self.frame1,text="Forgot Password",font=self.my_font1)
        self.title.place(x=310,y=150)
        self.entry=ctk.CTkLabel(self.frame1,text="Enter your email id or phone number. We will send an otp on your entered id or phone number",font=self.my_font, wraplength=770)
        self.entry.place(x=40,y=260)
        self.evar=ctk.CTkEntry(self.frame1,placeholder_text="Email Id or phone number", width=550,height=50,font=self.my_font2)
        self.evar.place(x=30,y=350)
        self.evar.focus_set()
        self.var=ctk.CTkButton(self.frame1,text="Verify",width=200,height=50,font=self.my_font,command=self.otpvar)
        self.var.place(x=610,y=350)
    def loginapp(self):
        self.frame1=ctk.CTkFrame(self,width=850,height=600)
        self.frame1.place(x=350,y=100)
        self.my_font = ctk.CTkFont(family="times new roman", size=30)
        self.btn1=ctk.CTkButton(self.frame1,text="Login",width=425,height=50,font=self.my_font,command=self.loginapp,state='disabled')
        self.btn1.place(x=0,y=0)
        self.btn2=ctk.CTkButton(self.frame1,text="Signin",width=425,height=50,font=self.my_font,command=self.signin,state='normal')
        self.btn2.place(x=425,y=0)
        self.check_var=ctk.StringVar(value="on")
        img = ctk.CTkImage(Image.open("image1.png"),size=(200,200))
        panel =ctk.CTkLabel(self.frame1, text="",image = img)
        panel.place(x=330, y=80)
        self.email1=ctk.CTkEntry(self.frame1,placeholder_text="Email Id or phone number",width=450)
        self.email1.place(x=200,y=300)
        self.passwd1=ctk.CTkEntry(self.frame1,placeholder_text="Password",width=450,show="*")
        self.passwd1.place(x=200,y=340)
        self.check=ctk.CTkCheckBox(self.frame1,text="Remember Me",variable=self.check_var,onvalue="on",offvalue="off")
        self.check.place(x=200,y=380)
        self.forgot = ctk.CTkLabel(self.frame1, text="Forgot Password", text_color="dodgerblue",cursor="hand2")
        self.forgot.bind("<Button-1>", lambda event: self.forget())
        self.forgot.place(x=550,y=380)
        self.submit=ctk.CTkButton(self.frame1,text="Login",command=self.verify1)
        self.submit.place(x=360,y=420)
    def verifyotp1(self):
        if(not self.evar1.get().strip()==" "):
            if(self.maxattempts==3):
                self.loginapp()
            else:
                if(self.evar1.get().strip()==str(self.otp)):
                    try:
                        passwd=self.encryption(self.email.get().lower().strip(),self.passwd.get().strip())
                        users_ref.push({"Name":self.name.get().title(),"Email Id or phone number":self.email.get().lower().strip(),"Password":base64.b64encode(passwd).decode('utf-8')})
                        self.loginapp()
                    except:
                        CustomMessageBox(message="Check your internet connecton")
                else:
                    self.maxattempts+=1
    def otpframe(self):
        self.frame1=ctk.CTkFrame(self,width=850,height=600)
        self.frame1.place(x=350,y=100)
        self.back=ctk.CTkButton(self.frame1,text="Back",width=850,height=50,font=self.my_font,command=self.signin)
        self.back.place(x=0,y=0)
        self.my_font1 = ctk.CTkFont(family="times new roman", size=40)
        self.my_font2 = ctk.CTkFont(family="times new roman", size=20)
        self.title=ctk.CTkLabel(self.frame1,text="Verify its you",font=self.my_font1)
        self.title.place(x=310,y=150)
        self.entry=ctk.CTkLabel(self.frame1,text="We will send an otp on your entered emailid or phone no. please enter it",font=self.my_font,wraplength=790)
        self.entry.place(x=40,y=260)
        self.evar1=ctk.CTkEntry(self.frame1,placeholder_text="OTP", width=550,height=50,font=self.my_font2)
        self.evar1.place(x=30,y=350)
        self.evar1.focus_set()
        self.var1=ctk.CTkButton(self.frame1,text="Verify",width=200,height=50,font=self.my_font,command=self.verifyotp1)
        self.var1.place(x=610,y=350)
    def userverify(self):
        if(self.name.get().strip()=="" or self.email.get().strip()==" " or self.passwd.get().strip()==" "):
            CustomMessageBox(message="All fields are required")
        elif(re.match(pattern,self.email.get().strip())):
            if(re.match(pattern1,self.email.get().strip())):
                if users_ref.get():
                    flag=0
                    for key, value in users_ref.get().items():
                        if value.get('Email Id or phone number') == self.email.get().lower().strip():
                            flag==1
                            break
                    if(flag==0):
                        try:
                            phone_number = phonenumbers.parse(self.email.get().strip())
                            if phonenumbers.is_valid_number(phone_number) and phonenumbers.is_possible_number(phone_number):
                                if(self.sendsms(self.email.get().strip())==True):
                                    self.otpframe()
                            else:
                                CustomMessageBox(message="Invalid phone number")
                        except Exception as e:
                            CustomMessageBox(message=e)
                    else:
                        CustomMessageBox(message="Already Registered")
                        self.email.delete(0,"end")
                        self.passwd.delete(0,"end")
                        self.email.focus_set()    
                else:
                    CustomMessageBox(message="Check your internet connection")
            else:
                CustomMessageBox(message="Please enter an indian number")
        elif(not re.fullmatch(regex,self.email.get().strip().lower())):
            CustomMessageBox(message="Invalid Email Id")
        elif(self.email.get().strip().lower().find(" ")!=-1):
            CustomMessageBox(message="Invalid Email Id")
        else:
            if users_ref.get():
                flag=0
                for key, value in users_ref.get().items():
                    if value.get('Email Id or phone number') == self.email.get().lower().strip():
                        flag=1
                        break
                if(flag==0):
                    if(self.sendemail(self.email.get().strip().lower())==True):
                        self.otpframe()
                    else:
                        CustomMessageBox(message="Check your internet connection")
                else:
                    CustomMessageBox(message="Already Registered")
                    self.email.delete(0,"end")
                    self.passwd.delete(0,"end")
                    self.email.focus_set()
            else:
                CustomMessageBox(message="Check your internet connection")
    def signin(self):
        self.maxattempts=0
        self.frame1=ctk.CTkFrame(self,width=850,height=600)
        self.frame1.place(x=350,y=100)
        self.btn1=ctk.CTkButton(self.frame1,text="Login",width=425,height=50,font=self.my_font,command=self.loginapp,state='normal')
        self.btn1.place(x=0,y=0)
        self.btn2=ctk.CTkButton(self.frame1,text="Signin",width=425,height=50,font=self.my_font,command=self.signin,state='disabled')
        self.btn2.place(x=425,y=0)
        img1 = ctk.CTkImage(Image.open("image1.png"),size=(200,200))
        panel =ctk.CTkLabel(self.frame1, text="",image = img1)
        panel.place(x=330, y=80)
        self.name=ctk.CTkEntry(self.frame1,placeholder_text="Name",width=450)
        self.name.focus_set()
        self.name.place(x=200,y=300)
        self.email=ctk.CTkEntry(self.frame1,placeholder_text="Email Id or Phone number",width=450)
        self.email.place(x=200,y=340)
        self.passwd=ctk.CTkEntry(self.frame1,placeholder_text="Password",width=450,show="*")
        self.passwd.place(x=200,y=380)
        self.submit=ctk.CTkButton(self.frame1,text="Signin",command=self.userverify)
        self.submit.place(x=360,y=420)