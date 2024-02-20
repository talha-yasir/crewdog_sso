import base64
from datetime import timedelta, datetime
import time
from django.core.mail import EmailMessage
from threading import Thread
from django.conf import settings
from google.oauth2 import service_account
from googleapiclient.discovery import build

def get_base64_image(path):
    if path:
        with open(path, 'rb') as image_obj:
            return base64.b64encode(image_obj.read()).decode("ascii")
        



class EmailThread(Thread):
    def __init__(self, subject, html_message, recipient_list):
        self.subject = subject
        self.html_messages = html_message
        self.recipient = recipient_list
        Thread.__init__(self)

    def run (self):
        msg = EmailMessage(subject = self.subject, body = self.html_messages, from_email = settings.DEFAULT_FROM_EMAIL, bcc = self.recipient)
        msg.content_subtype = "html"
        msg.send()


def get_service():
    SERVICE_ACCOUNT_FILE = 'googlesheet_service_account.json'  
    SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
    credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    service = build('sheets', 'v4', credentials=credentials)
    return service