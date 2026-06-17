from pathlib import Path

sent_messages_folder = Path('sent_messages')

def make_file(message: bytes, file_name: str):
    global sent_messages_folder

    file_path = sent_messages_folder / file_name

    sent_messages_folder.mkdir(parents=True, exist_ok=True)

    file_path.write_bytes(message)

def read_file(file_name: str):
    # TODO
    pass