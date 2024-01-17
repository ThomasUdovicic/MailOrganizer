from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from tqdm import tqdm
import base64
# import re
import pickle
import os
import csv

# If modifying these SCOPES, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']


def service_gmail():
    creds = None
    # The file token.pickle stores the user's access and refresh tokens.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)
    return service


def search_emails(service, query):
    all_messages = []
    request = service.users().messages().list(userId='me', q=query)

    while request is not None:
        response = request.execute()
        messages = response.get('messages', [])
        all_messages.extend(messages)
        request = service.users().messages().list_next(previous_request=request, previous_response=response)

    return all_messages


def get_message_detail(service, msg_id):
    # Get the detail of a specific message
    message = service.users().messages().get(
        userId='me', id=msg_id, format='full').execute()
    return message


def decode_message_part(data):
    # Decode base64 URL encoded mail content
    byte_code = base64.urlsafe_b64decode(data.encode('ASCII'))
    return byte_code.decode('utf-8')


def find_nearby_links(html_content, keywords, proximity=5):
    soup = BeautifulSoup(html_content, 'html.parser')
    text_with_links = []

    for tag in soup.find_all('a', href=True):
        previous_text = ''
        next_text = ''

        # Handle previous siblings
        prev_sib = tag.previous_sibling
        while prev_sib and len(previous_text.split()) < proximity:
            if isinstance(prev_sib, str):
                previous_text = prev_sib + ' ' + previous_text
            prev_sib = prev_sib.previous_sibling

        # Handle next siblings
        next_sib = tag.next_sibling
        while next_sib and len(next_text.split()) < proximity:
            if isinstance(next_sib, str):
                next_text = next_text + ' ' + next_sib
            next_sib = next_sib.next_sibling

        full_text = ' '.join([previous_text.strip(), tag.get_text(), next_text.strip()])
        
        if any(keyword in full_text.lower() for keyword in keywords):
            text_with_links.append(tag['href'])

    return text_with_links


def extract_domain(url):
    # Extracts the domain name from a URL
    parsed_url = urlparse(url)
    return parsed_url.netloc


def trash_email(service, msg_id):
    try:
        service.users().messages().trash(userId='me', id=msg_id).execute()
        print(f"Message ID to trash: {msg_id}")
    except Exception as e:
        print(f"Error momving to trash message ID {msg_id}: {e}")


def delete_email(service, msg_id):
    try:
        service.users().messages().delete(userId='me', id=msg_id).execute()
        print(f"Message ID to trash: {msg_id}")
    except Exception as e:
        print(f"Error momving to trash message ID {msg_id}: {e}")


def move_email_to_spam(service, msg_id):
    try:
        # "SPAM" is typically the label ID for spam, but this can be confirmed by listing labels.
        spam_label_id = 'SPAM'
        service.users().messages().modify(
            userId='me', 
            id=msg_id, 
            body={'addLabelIds': [spam_label_id]}
        ).execute()
        print(f"Moved message ID: {msg_id} to Spam")
    except Exception as e:
        print(f"Error moving message ID {msg_id} to Spam: {e}")


def main():
    service = service_gmail()
    query = 'unsubscribe OR afmelden'
    messages = search_emails(service, query)
    keywords = ['unsubscribe', 'afmelden']
    unsubscribe_email_count = 0
    deletion_treshold = 1 # Sets threshold how many emails received before deleting all of them

    # Init batch request
    batch = service.new_batch_http_request()
    batch_counter = 0

    with open('unsubscribe_links.csv', 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Subject', 'Sender', 'Website', 'Unsubscribe Link'])

        for message in tqdm(messages, desc='Processing emails'):  # tqdm shows a progress bar for the loop
            msg_detail = get_message_detail(service, message['id'])
            payload = msg_detail.get('payload', {})
            headers = payload.get('headers', [])
            subject = next(header['value'] for header in headers if header['name'].lower() == 'subject')
            sender = next(header['value'] for header in headers if header['name'].lower() == 'from')

            unsubscribe_links = set()
            parts = payload.get('parts', [])
            for part in parts:
                body_data = part['body'].get('data', '')
                body = decode_message_part(body_data)

                if part['mimeType'] == 'text/html':
                    links = find_nearby_links(body, keywords)
                    unsubscribe_links.update(links)
            
            if unsubscribe_links:
                unsubscribe_email_count += 1
                if unsubscribe_email_count >= deletion_treshold:
                    # trash_email(service, message['id'])  # Use either trash or move to spam
                    # move_email_to_spam(service, message['id'])
                    batch.add(service.users().messages().trash(userId='me', id=message['id']))
                    batch_counter += 1

                    if batch_counter == 50:
                        batch.execute()
                        batch = service.new_batch_http_request()
                        batch_counter = 0

            for link in unsubscribe_links:  # Use a set to remove duplicatesCan 
                website = extract_domain(link)
                writer.writerow([subject, sender, website, link])

        if batch_counter > 0:
            batch.execute()


if __name__ == '__main__':
    main()
