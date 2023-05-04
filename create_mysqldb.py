import mysql.connector

mydb = mysql.connector.connect(host="34.100.178.136", user="gwcuser", passwd="gwcuser")

mycursor = mydb.cursor()

# mycursor.execute("CREATE DATABASE gwcpmp")

#mycursor.execute("SHOW DATABASES")
#for db in mycursor:
#    print(db)