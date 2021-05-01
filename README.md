# ElementorHW
Elementor Data Engineer Task

For this task I used sqlite3 on Pyhton in order to create the database (sites.db).
It will create (if not yet exists) a table called 'sites', and query all the sites that appear in DS1.csv file (given that it was not queried in the last 30 minutes) and retrieve the information needed to the database table.
To add/remove sites to check just add/remove urls inside DS1 file.
I used DB Browser for SQLite to view the database.

To run code you will need to 'pip install vt-py' (this is the library that inteacts with VirusTotal API) and then run 'python main.py'.
I ran it from PyCharm IDE.

Answers to SQL questions are in sepearte .txt files (SQL_Q1 and SQL_Q2)
