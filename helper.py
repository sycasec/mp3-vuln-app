import datetime

def sanitize(message: str):
    return message.translate(str.maketrans({'<':"&lt", '>':"&gt"}))

def is_rate_limited(cur, remote_address):

    LIMIT_WINDOW = 5*60              # 5 minutes
    MAX_ATTEMPTS_PER_WINDOW = 10     # only allow 10 attempts per 5 minutes
    
    res = cur.execute("""SELECT timestamp 
                            FROM login_attempts 
                            WHERE remote_address=? 
                                AND unixepoch(?)-unixepoch(timestamp)<=?""", 
                                [remote_address, datetime.datetime.now(), LIMIT_WINDOW])
    attempts = res.fetchall()
    if len(attempts) > MAX_ATTEMPTS_PER_WINDOW:
        return True
    
    return False
