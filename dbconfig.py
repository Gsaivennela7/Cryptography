from dotenv import load_dotenv,find_dotenv 
import os
from pymongo import MongoClient

def connectDb():
    #load the environment variables
    load_dotenv(find_dotenv())
    string_Conn = os.environ.get("MONGO")

    #connect to the MONGO DB
    connection_String = string_Conn
    client = MongoClient(connection_String)

    #get the DB and collection information
    db = client.Crypt
    
    return db
 
def verifyUser(db,busNumber):
    collectionBus = db.Bus
    busNumber = int(busNumber)
    result = collectionBus.find_one({"busNumber":busNumber})
    if result is not None:
        return True
    else:
        return False


  






