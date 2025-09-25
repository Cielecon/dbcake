# dbcake
<img src="https://github.com/Cielecon/dbcake/blob/main/dbcake.png" width="300"/>

a python database library that you can make your python projects easily with dbcake!
**what does it do?** you can save your datas like *passwords* and *usernames* and lots of things... easily,
with out any pain! and just in 3 lines!
dbcake has high security and you can use it on **linux , windows , macos and ...**
if you like this project , please star⭐ and send feedbacks :)

# Learn how to use

at first you need to import library
```python
import dbcake
```
now you used library! so lets set a table!

```python 
dbcake.db.set("username", "armin")
```
now you saved a username that it name is armin so lets get username


```python 
dbcake.db.get("username")
```
Output:

```python 
armin
```
now you get output! so lets make password!

```python
dbcake.db.pw= "high" # low | normal | high
dbcake.db.secret = {pin: 1234} 
print (dbcake.db.preview()) # preview table
```
# connection with SQL
you can connect dbcake to **SQL** just with easy steps!
```python
#use the default sql connection (points at database.db)
database.sql.create_table("notes", {"id":"INTEGER PRIMARY KEY","title":"TEXT","body":"TEXT"})
notes = database.sql.table("notes")
notes.insert({"title":"Hello","body":"First note"})
print(notes.select(["id","title"]).all())
#raw SQL
rows = database.sql.query("SELECT COUNT(*) AS cnt FROM notes")

print(rows)
```
# Using an independent SQL file
```python
from database import open_sql
db = open_sql("myapp.db")
db.create_table("users", {"id":"INTEGER PRIMARY KEY","name":"TEXT","age":"INTEGER"})
tbl = db.table("users")
tbl.insert({"name":"Armin","age":33})
print(tbl.select(["id","name"]).where("age > ?", (20,)).all())
db.close()
```
# Joins (basic usage)
```python
#create tables and use join clause
database.sql.create_table("authors", {"id":"INTEGER PRIMARY KEY","name":"TEXT"})
database.sql.create_table("posts", {"id":"INTEGER PRIMARY KEY","author_id":"INTEGER","title":"TEXT"})
database.sql.table("authors").insert({"name":"A"})
database.sql.table("posts").insert({"author_id":1,"title":"Hi"})
rows = database.sql.table("posts").select(["posts.id","posts.title","authors.name"]).join("INNER JOIN authors ON authors.id = posts.author_id").all()
print(rows)
```
>[!CAUTION]
>please read LICENSE and ©️ copyright by Cielecon all rights reversed.
