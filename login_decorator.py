from functools import wraps
from flask import redirect
from flask import session as login_session

def login_required(f):
    '''Check user status (logged in/out)'''
    @wraps(f)
    def x(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        return f(*args, **kwargs)
    return x