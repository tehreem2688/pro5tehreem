#develop a streamlit_based secure data storage and retrieval system 
#instruction:TEHREEM FATIMA
 
import streamlit as st
import hashlib
import json
import os
import time
from cryptogarphy.fernet import fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === data information of use ===
DATA_FILE = "secure_data.json"
SALT = "secure_salt_value"
LOCKOUT_DURATION = 60


# === section login details ===
if "authentic_user" not in st.session_state:
    st.session_state.authentic_user = None 

if "failed_attempt" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === if data is load ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE,"r") as f:
            return json.laod(f)
    return {}

def save_data(data):
    with open(DATA_FILE,"w") as f:
        json.dump(data, f)

def generation_key(passkey):
    key = pbkdf2_hmac('sha256' , passkey.encode(), SALT ,100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256' , password.encode(), SALT ,100000).hex()


# === cryptography.fernet used ===
def encrypt_text(text,key):
    cipher = fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text , key):
    try:
        cipher = fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None
    
stored_data = load_data()

    # === navigation bar ===
st. title("🔐secure data Encryption system")
menu = ["home","register" , "login" , "store data" , "retrieve data"]
choice = st. sidebar.selectbox("navigation", menu)

if choice == "Home":
    st.subheader("welcome to my data encryption system using streamlit !")
    st.markdown("develop a streamlit-based secure data storage and retrieval system where: users store data with a unique passkey. users decrypt data by providing the correct passkey. Multiple failed attempts result in a forced reauthorization(login page). the system operates entirely in memory without external databases.")
    
# === user registration ===
elif choice == "register":
    st.subheader("💻Register new user")
    username = st.text_input("choose username")
    password = st.text_input("choose password",type="password")

    if st.button("register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️user already exisits.")
            else:
                stored_data[username]={
                     "password":hash_password(password),
                     "data" : []
                }
                save_data (stored_data)
                st.success("✅user register sucessfully!")
        else:
            st.error("both fields are required.")

    elif choice == "login":
        st.subheader("🔑user login")

        if time.time() < st.session_state.lockout_time:
            remaning = int(st.session_state.lockout_time - time.time())
            st.error(f"⏱️Too many failed attempts.please wait {remaining} seconds.")
            st.stop()

        userrname = st.text_input("username")
        password = st.text_input("password", type="password")

        if st.button("login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
               st.session_state.authenticated_user = username
               st.session_state.failed_attempts = 0
               st. success(f"✅welcome {username}!")
            else:
                st.session_state.failed_attempts
                remaning = 3 - st.session_state.failed_attempts
                st.error(f"❌Invalid credentials! attempts left: {remaining}") 
                
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("🔴To many failed attempt.locked for 60 seconds")
                    st.stop()

# === data store section ===
elif choice == "store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒please logic first.")
    else:
        st.subheader("📦store Encrypted Data")
        data = st.text_area("Enter data to encrepty")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        
        if st.button("Encrypt And Save"):
            if data and passkey:
                encrypted = encrypt_text(data,passkey)
                stored_data[st.session_state.authenticated_use]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅Data encrypted and save sucessfully!")

            else:
                st.error("all fields are required to fill.")
        # === data retieve data section ===
        elif choice == "Retieve Data":
            if not st.session_state.authenticated_user:
                st.warning("🔓please login first")
            else:
                st.subheader("🔍Retieve data")
                user_data = stored_data.get(st.session_state.authentic_user,{}).get("data",[])
                if not user_data:
                    st.info("No Data Found!")
                else:
                    st.write("Encryted Data Enteries:")
                    for i,item in enumerate(user_data):
                        st.code(item,language="text")

                    encrypted_input = st.text_area("Enter Encrypted Text")
                    passkey = st.text_input("Enter Passkey T Decrypt", type="password")

                    if st.button("Decrypt"):
                        result = decrypt_text(encrypted_input,passkey)
                        if result:
                            st.success(f"✅Decrypted : {result}")
                        else:
                            st.error("❌Incorrect passkey or carrupted data.")