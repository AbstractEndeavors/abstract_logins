from abstract_database import *
connectionManager(host='192.168.1.100',port="5432",
                  dbName='abstract_base',user='admin',password="F0D011bGUuAWsiyU")

from imports import *

user_store= get_user_store()
input(user_store.get_existing_users())
input(user_store.add_or_update_user('joben','joben',is_admin=True))
input(user_store.get_existing_users())
