from flask import Flask
from pymongo import MongoClient
from app import *


app = Flask(__name__)
MONGODB_URI = 'mongodb://localhost:27017/your_database'
mongo = MongoClient(MONGODB_URI)
