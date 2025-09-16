from login_app.functions import *
import glob
from abstract_utilities import *
from abstract_apis import *
from abstract_database import *
conn_mgr = connectionManager()
input(conn_mgr.dburl)


#input(get_existing_users())
#upsert_admin("Very$ecureAdminPass1")
def get_call(endpoint):
    url = f'https://abstractendeavors.com/secure-files/{endpoint}'
    headers = get_headers()
    response = postRequest(url,data={},headers=headers)
    return response
def get_url_endpoint(line):
    if '(' in line:
        endpoint = line.split('(')[1].split(')')[0].split(',')[0]
        endpoint = eatAll(endpoint,['"',"'",'/'])
        return endpoint
def get_method(line):
    method = ['GET']
    if 'methods=' in line:
        method = eatAll(line.split('methods=')[-1],['[',']',"'",'"',')','(']).replace('"','').replace("'",'').split(',')
    return method
def get_endpoints(line):
    get_url_endpoint(line)
    url = f'https://abstractendeavors.com/secure-files/{endpoint}'
    
    return {"url":[url],"method":method,"function":[]}
def get_all_ends(data):
   alls = []
   lines = data.split('\n')
   started = False
   tabbed=False
   for i,line in enumerate(lines):
       if line.startswith('@'):
           
           if started == False:
               alls.append({"url":[],"method":[],"function":[]})
               alls[-1]["url"].append(get_url_endpoint(line))
               alls[-1]["method"]+=get_method(line)
           started=True
           
           for line_init in lines[i:]:
               
               if line_init.startswith('\t') or line_init.startswith(' ') or line_init.startswith('#'):
                   tabbed = True
                   
               elif (line_init.startswith('def') or line_init.startswith('@')) and tabbed == True:
                    tabbed=False
                    started=False
                    print('\n'.join(alls[-1]["function"]))
                    break
               alls[-1]["function"].append(line_init)
   return alls
directory = '/var/www/abstractendeavors/secure-files/big_man/flask_app/login_app/endpoints'
import glob, os
all_paths = glob.glob(os.path.join(directory, "**", "*.py"), recursive=True)
all_files = [p for p in all_paths if os.path.isfile(p)]
all_ends = []
for pyfile in all_files:
    data = read_from_file(pyfile)
    all_ends+=get_all_ends(data)
    

input(all_ends)


