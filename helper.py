import datetime

def sanitize(message: str):
    return message.translate(str.maketrans({'<':"&lt", '>':"&gt"}))

