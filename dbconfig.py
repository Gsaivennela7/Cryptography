from dotenv import load_dotenv,find_dotenv 
import os
import pprint
from pymongo import MongoClient
from gridfs import GridFS
import cv2
import face_recognition as fr
import os
import pickle
import numpy as np
import PIL.Image as Image 
import io
import base64

passengers = []
accountIds = []
image_document = []
imagesList =[]
passengerIds=[]
def connectDb():
    #load the environment variables
    load_dotenv(find_dotenv())
    password = os.environ.get("MONGODB_PWD")

    #connect to the MONGO DB
    connection_String = "mongodb+srv://sai_vennela:Welcome1%40@cluster0.kdsr51a.mongodb.net/?retryWrites=true&w=majority"
    client = MongoClient(connection_String)

    #get the DB and collection information
    db = client.Happi_Bus
    
    return db
 
def verifyUser(db,busNumber):
    collectionBus = db.Bus
    busNumber = int(busNumber)
    result = collectionBus.find_one({"busNumber":busNumber})
    if result is not None:
        return True
    else:
        return False


  






