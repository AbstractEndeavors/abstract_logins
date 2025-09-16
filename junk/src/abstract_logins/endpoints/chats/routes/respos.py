from abstract_apis import *
from abstract_utilities import *
CONVO_URL = "https://abstractendeavors.com/secure-files/get_convo_data"    
class responseManager(metaclass=SingletonMeta):
    def __init__(self,url=CONVO_URL):
        if not hasattr(self, 'initialized') or self.initialized == False:
            self.initialized = True
            self.response = getRequest(url)
def get_response_data():
    resp_mgr = responseManager()
    response = resp_mgr.response
    return response
def get_conversation_id(data):
    value = data.get('conversation_id')
    if value:
        return value
def search_for_general_id(general_id=None):
    if conversation_id:
        response_datas = get_response_data()
        for response_data in response_datas:
            gen_id = response_data.get('id')
            if gen_id == general_id:
                return response_data
def search_for_conversation_id(conversation_id=None):
    if conversation_id:
        response_datas = get_response_data()
        for response_data in response_datas:
            conv_id = response_data.get('conversation_id')
            if conv_id == conversation_id:
                return response_data
def get_mappinng(data=None,conversation_id=None):
    data = data or search_for_conversation_id(conversation_id)
    mapping = data.get('mapping')
    return mapping
def get_children(data=None,conversation_id=None):
    children=[]
    mapping = get_mappinng(data=data,conversation_id=conversation_id)
    for key,value in mapping.items():
        children.append(value.get('children'))
    return children
for respo in get_response_data():
    for key,value in respo.items():
        if key == 'mapping':
            break
        print(f"{key}:{value}")
    repo_id = respo.get('id')
    conversation_id = respo.get('conversation_id')
    children = get_children(conversation_id=conversation_id)
    for childs in children:    
        for child_id in childs:
                conversation = search_for_general_id(general_id=child_id)
                input(conversation)
