import imaplib, time, logging
log=logging.getLogger(__name__)

def fetch_unseen_once(username, app_password, imap_server, folder, analyze_callback, quarantine_folder='Quarantine'):
    count=0
    with imaplib.IMAP4_SSL(imap_server) as mail:
        mail.login(username,app_password); status,_=mail.select(folder or 'INBOX')
        if status!='OK': return 0
        status,data=mail.search(None,'UNSEEN')
        if status!='OK': return 0
        for mid in data[0].split():
            status,msg=mail.fetch(mid,'(RFC822)')
            if status!='OK': continue
            raw=next((x[1] for x in msg if isinstance(x,tuple) and len(x)==2),None)
            if not raw: continue
            result=analyze_callback(raw, source='imap')
            if isinstance(result,dict) and result.get('classification') in {'Phishing','Critical'}:
                try: mail.copy(mid,quarantine_folder)
                except imaplib.IMAP4.error: log.warning('Could not copy message %s to %s',mid,quarantine_folder)
            count+=1
    return count

def poll_inbox(username, app_password, imap_server, analyze_callback, folder='INBOX', interval=20):
    while True:
        fetch_unseen_once(username,app_password,imap_server,folder,analyze_callback); time.sleep(max(5,interval))
