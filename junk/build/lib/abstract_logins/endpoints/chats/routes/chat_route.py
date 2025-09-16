from abstract_flask import parse_request,request
from ...imports import *
from ....functions.chat_utils import *
secure_chat_bp, logger = get_bp(
    "secure_chat_bp",
    __name__,
    static_folder=STATIC_FOLDER,
    url_prefix=URL_PREFIX
)

def get_convo_file_path(request):
    args,kwargs = parse_request(request)
    file_path = kwargs.get('file_path')
    if not file_path:
        directory = kwargs.get('directory') or ABS_PUBLIC_FOLDER
        file_path = get_conversation_path(directory)
    return file_path
@secure_chat_bp.route('/chat-exports', methods=['GET'])
@login_required
def get_chats():
    initialize_call_log()
    try:
        query = """
                    SELECT id, message, created_at
                    FROM chats
                    ORDER BY created_at
                    DESC LIMIT 100;
                """
        row = select_rows()
        if row is None:
            return get_json_call_response(value="File not found.",
                                          logMsg=f"DB error in get_chats: id and message and created_at not located in db from ",
                                          status_code=404)
        payload = [dict(id=r[0],
                    message=r[1],
                    created_at=r[2].isoformat()
                    ) for r in row]
        return jsonify({ 'chats': payload })                                  
    except Exception as e:
        return get_json_call_response(value="Database error.",
                                      logMsg=f"DB error in get_chats (fetch): {e}",
                                      status_code=500)
    
@secure_chat_bp.route('/search_in_conversation', methods=['GET','POST'])
#@login_required
def searchInConversation():
    try:
        initialize_call_log()
    
        args,kwargs = parse_request(request)
        file_path = kwargs.get('file_path')
        if not file_path:
            directory = kwargs.get('directory') or ABS_PUBLIC_FOLDER
            file_path = get_conversation_path(directory)
        kwargs['file_path'] = file_path
        strings = kwargs.get('strings')
        for string in ['directory','strings']:
            if string in kwargs:
                del kwargs[string]
        data_found = search_in_conversation(strings=strings, *args, **kwargs)
        return get_json_call_response(value=data_found,status_code=200)
    except Exception as e:
        return get_json_call_response(value="Database error.",
                                      logMsg=f"DB error in search_in_conversation (fetch): {e}",
                                      status_code=500)



@secure_chat_bp.route('/get_convo_data', methods=['GET','POST'])
#@login_required
def getConvoData():
    initialize_call_log()
    try:
       
        file_path = get_convo_file_path(request)
        data_found = get_convo_data(file_path=file_path)
        return get_json_call_response(value=data_found,status_code=200)
    except Exception as e:
        return get_json_call_response(value="Database error.",
                                      logMsg=f"DB error in getConvoData (fetch): {e}",
                                      status_code=500)
