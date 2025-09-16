import os
from abstract_ai.gpt_classes.response_selection.search_responses import *
from ..paths import ABS_PUBLIC_FOLDER
def get_chat_dir(directory=None):
    directory = directory or ABS_PUBLIC_FOLDER
    chat_dir = os.path.join(directory,'chat_dir')
    return chat_dir
def get_conversation_path(directory=None):
    chat_dir = get_chat_dir(directory=directory)
    conversation_path = os.path.join(chat_dir,'conversations.json')
    return conversation_path

