import random

import flask
import pymongo
import bcrypt
import os
import hashlib

from flask import Flask
from pymongo import MongoClient

mongo_client = MongoClient("mongo")
db = mongo_client["carwashapp"]
chat_collection = db["chat"]
user_collection = db["user"]
odupy8epojgda
app = Flask(__name__)

#给root path 发送response
@app.route('/')
def serve_root():
    auth_token=flask.request.cookies.get('auth_token')
    #如果用户已经登录，在request中获取auth_token
    if auth_token and user_collection.find_one({"auth_token":hashlib.sha256(auth_token.encode()).digest()}) is not None:
        if user_collection.find_one({"auth_token": hashlib.sha256(auth_token.encode()).digest()}) is not None:
            username=user_collection.find_one({"auth_token":hashlib.sha256(auth_token.encode()).digest()})["username"]
            #如果用户已经登录，通过token获取username发送已登录状态的response
            return flask.render_template('index.html',username=username)
    return flask.render_template('index.html')

@app.route('/register', methods=['POST'])
def serve_register():
    username=flask.request.form.get('Rusername')
    password=flask.request.form.get('Rpassword')
    salt=bcrypt.gensalt()
    #为密码的加密增加salt
    if(user_collection.find_one({"username":username}) is None):
        user_collection.insert_one({"username":username,"password":bcrypt.hashpw(password.encode("utf-8"),salt)})
    return flask.redirect(flask.url_for('serve_root'))

@app.route('/login', methods=['POST'])
def serve_login():
    username = flask.request.form.get('Lusername')
    password = flask.request.form.get('Lpassword')
    auth_token=random.randint(1,100000000000000000000)
    hashed_token=hashlib.sha256(str(auth_token).encode()).digest()
    if(user_collection.find_one({"username":username}) is not None):
        user=user_collection.find_one({"username":username})
        for i in range(10):
            print(user)
        if bcrypt.checkpw(password.encode(),user["password"]):
            user_collection.update_one({"username": username}, {'$set': {"auth_token": hashed_token}})
            # return flask.render_template('index.html',auth_token=auth_token)
    return flask.redirect(flask.url_for('serve_root'))

@app.route('/logout',methods=['POST'])
def serve_logout():
    auth_token=flask.request.cookies.get('auth_token')
    if auth_token:
        hashed_token = hashlib.sha256(str(auth_token).encode()).digest()
        if user_collection.find_one({"auth_token": hashed_token}) is not None:
            usernameindb = user_collection.find_one({"auth_token": hashed_token})
            username = usernameindb["username"]
            user_collection.update_one({"username": username}, {'$unset': {"auth_token": hashed_token}})
    return flask.redirect(flask.url_for('serve_root'))






if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)