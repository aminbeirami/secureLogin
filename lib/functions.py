from werkzeug.security import generate_password_hash, check_password_hash
from lib import mySQLCon as mc
from lib import keyGen as kg
from lib.config import *
from random import randint
import os

def save_user_pass(userData,db):
    userid = randint(0,100)
    sql = "INSERT INTO users (uid,username,password,isadmin) VALUES (%s,%s,%s,%s)"
    username = userData[0][1]
    password = generate_password_hash(userData[1][1])
    parameters = (userid, username, password, False)
    db.insert(sql, parameters)
    return userid, username

def save_pub_priv(userid,publickey,privatekey,db):
    keyid = randint(0,100)
    sql = "INSERT INTO securekeys (keyid,userid,publickey,privatekey) VALUES (%s,%s,%s,%s)"
    parameters = (keyid, userid, publickey, privatekey)
    db.insert(sql, parameters)

def save_pub_key(userid,username,publickey,db):
    keyid = randint(0,100)
    sql = "INSERT INTO publickeys (keyid,username,publickey,userid) VALUES (%s,%s,%s,%s)"
    parameters = (keyid, username, publickey, userid)
    db.insert (sql, parameters)

def hashing_and_save(user_list):
    keyGen = kg.RSAEncryption()
    publickey, privatekey = keyGen.generate_keys()
    db = connect_to_DB()
    userid, username = save_user_pass(user_list,db)
    save_pub_priv(userid,publickey,privatekey,db)
    save_pub_key(userid,username,publickey,db)
    db.commit()

def connect_to_DB():
    if os.getenv('SERVER_SOFTWARE', '').startswith('Google App Engine/'):
        db = mc.DataBase(CLOUDSQL_CONNECTION_NAME,CLOUDSQL_USER,CLOUDSQL_PASSWORD,CLOUDSQL_DATABASE,'GCSQL')
    else:
        db = mc.DataBase(SERVER,USERNAME,PASSWORD,DATABASE,'LOCAL')
    return db


def fetch_username_and_password(username,password):
    db = connect_to_DB()
    sql = "SELECT * FROM users WHERE username = %s"
    arguments = (username,)
    result = db.query(sql,arguments)
    if result:
        authentication = check_password_hash(result[0][2],password)
        if authentication:
            if result[0][3] == 1:
                isadmin = True
            else:
                isadmin = False
            return (True,isadmin)
        else:    
            return (False,False)
    else:
        return (False,False)