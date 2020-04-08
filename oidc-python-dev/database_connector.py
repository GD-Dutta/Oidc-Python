hostname = 'localhost'
username = 'root'
password = ''
database = 'gluu_server'

# Simple routine to run a query on a database and print the results:
def doQuery( conn ) :
    cur = conn.cursor()

    sql = "INSERT INTO `user_details`(`name`, `given_name`, `family_name`, `email`, `sub`) VALUES (%s, %s,%s,%s,%d)"
    val = (name, givenName, family_name, email, user_id)
    cur.execute(sql, val)
    conn.commit()

    sqlQuery = "select * from user_details"
    cur.execute(sqlQuery)

    rows = cur.fetchall()

    for row in rows:
        print(row)

print ("Using pymysql…")
import pymysql
myConnection = pymysql.connect( host=hostname, user=username, passwd=password, db=database )
doQuery( myConnection )
myConnection.close()