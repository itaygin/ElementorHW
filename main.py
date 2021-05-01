import vt
import csv
import sqlite3
import datetime

API_KEY = "1b6bee2719605f22acf29ad2f335c7df7d9e11b471a1c05ea54ea8e6fc61156a"
DATA_SOURCE_1 = "DS1.csv"
DB_NAME = "sites.db"
DATETIME_FORMAT = "%m/%d/%Y, %H:%M:%S"
REFRESH_TIME = 30


def get_vt_client():
    print("Connecting to VirusTotal API...")
    vt_client = vt.Client(API_KEY)
    return vt_client


def get_sites_list(input_file):
    print("Getting list of sites to check (from DS1.csv)...")
    sites_list = []
    with open(input_file) as csv_file:
        csv_reader = csv.reader(csv_file)
        for line in csv_reader:
            sites_list += line
    return sites_list


def get_db_con(db_name):
    con = None
    try:
        print("Connecting to sqlite DB...")
        con = sqlite3.connect(db_name)
    except sqlite3.Error as e:
        print(e)
    return con


def update_db(con, vt_client, sites_list):
    print("Updating DB with sites info...")
    cur = con.cursor()
    query = 'CREATE TABLE IF NOT EXISTS sites(' \
            'site_url TEXT PRIMARY KEY NOT NULL,' \
            'site_risk TEXT NOT NULL,' \
            'total_voting TEXT NOT NULL,' \
            'classification TEXT NOT NULL,' \
            'last_query_time TEXT NOT NULL)'
    cur.execute(query)
    for site in sites_list:
        query = 'SELECT last_query_time FROM sites WHERE site_url=\'' + site + '\''
        cur.execute(query)
        data = cur.fetchone()
        if data:
            last_query_time = datetime.datetime.strptime(data[0], DATETIME_FORMAT)
            time_diff = get_time_diff(last_query_time)
            if time_diff < REFRESH_TIME:
                continue
            else:
                query = 'DELETE FROM sites WHERE site_url=\'' + site + '\''
                cur.execute(query)
        values = get_site_values(site, vt_client)
        query = 'INSERT INTO sites VALUES ' + values
        cur.execute(query)
    con.commit()
    con.close()


def get_time_diff(query_time):
    curr_time = datetime.datetime.now()
    diff = curr_time - query_time
    diff_in_min = diff.total_seconds() / 60
    return diff_in_min


def get_site_values(site, vt_client):
    url_id = vt.url_id(site)
    url_info = vt_client.get_object("/urls/{}", url_id)
    val_list = []
    site_url = site
    last_analysis = dict(url_info.get('last_analysis_stats'))
    if last_analysis['malicious'] or last_analysis['suspicious']:
        site_risk = "risk"
    else:
        site_risk = "safe"
    total_voting = str(last_analysis)
    classification_dict = {}
    categories = dict(url_info.get('categories'))
    for item, category in categories.items():
        if category in classification_dict:
            classification_dict[category] += 1
        else:
            classification_dict[category] = 1
    classification = str(classification_dict)
    curr_time = datetime.datetime.now()
    query_time = curr_time.strftime(DATETIME_FORMAT)
    val_list.append(site_url)
    val_list.append(site_risk)
    val_list.append(total_voting)
    val_list.append(classification)
    val_list.append(query_time)
    values = str(val_list)
    return values.replace("[", "(", 1).replace("]", ")", 1)


if __name__ == '__main__':
    vt_client = get_vt_client()
    db_con = get_db_con(DB_NAME)
    sites_list = get_sites_list(DATA_SOURCE_1)
    update_db(db_con, vt_client, sites_list)
    vt_client.close()
    print("Done.")

