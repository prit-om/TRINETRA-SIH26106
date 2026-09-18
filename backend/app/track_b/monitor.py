from __future__ import annotations
import threading, time, logging
from .imap_ingestion import fetch_unseen_once
log=logging.getLogger(__name__)
_state={"running":False,"last_error":"","processed":0,"started_at":None}

def status(): return dict(_state)

def start(username,password,server,folder,callback,interval=20):
    if _state['running']: return status()
    _state.update(running=True,last_error='',started_at=time.time())
    def loop():
        while _state['running']:
            try: _state['processed'] += fetch_unseen_once(username,password,server,folder,callback)
            except Exception as exc: _state['last_error']=str(exc); log.exception('IMAP monitor error')
            time.sleep(max(5,int(interval)))
    threading.Thread(target=loop,daemon=True,name='trinetra-imap-monitor').start(); return status()

def stop(): _state['running']=False; return status()
