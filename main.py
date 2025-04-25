import wx
import os
import json
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import secrets

VAULT_FILE = "vault.enc"
SALT_SIZE = 16
ITERATIONS = 100_000


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


class PasswordManagerApp(wx.Frame):
    def __init__(self, parent, title, vault_data, fernet, salt):
        super().__init__(parent, title=title, size=(600, 450))
        self.fernet = fernet
        self.vault_data = vault_data
        self.filtered_data = vault_data.copy()
        self.salt = salt

        panel = wx.Panel(self)
        vbox = wx.BoxSizer(wx.VERTICAL)

        # Search Box
        search_box = wx.BoxSizer(wx.HORIZONTAL)
        self.search_ctrl = wx.TextCtrl(panel)
        self.search_ctrl.Bind(wx.EVT_TEXT, self.on_search)
        search_box.Add(wx.StaticText(panel, label="Search:"), flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=8)
        search_box.Add(self.search_ctrl, proportion=1)

        # Grid
        self.grid = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.grid.InsertColumn(0, 'Site', width=180)
        self.grid.InsertColumn(1, 'Username', width=180)
        self.grid.InsertColumn(2, 'Password', width=180)

        # Buttons
        hbox = wx.BoxSizer(wx.HORIZONTAL)
        add_btn = wx.Button(panel, label="Add Entry")
        del_btn = wx.Button(panel, label="Delete Selected")
        copy_user_btn = wx.Button(panel, label="Copy Username")
        copy_pass_btn = wx.Button(panel, label="Copy Password")

        add_btn.Bind(wx.EVT_BUTTON, self.on_add)
        del_btn.Bind(wx.EVT_BUTTON, self.on_delete)
        copy_user_btn.Bind(wx.EVT_BUTTON, self.copy_username)
        copy_pass_btn.Bind(wx.EVT_BUTTON, self.copy_password)

        hbox.Add(add_btn, flag=wx.RIGHT, border=5)
        hbox.Add(del_btn, flag=wx.RIGHT, border=5)
        hbox.Add(copy_user_btn, flag=wx.RIGHT, border=5)
        hbox.Add(copy_pass_btn)

        vbox.Add(search_box, flag=wx.EXPAND | wx.ALL, border=10)
        vbox.Add(self.grid, proportion=1, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=10)
        vbox.Add(hbox, flag=wx.ALIGN_CENTER | wx.ALL, border=10)

        panel.SetSizer(vbox)

        self.load_vault()
        self.Centre()
        self.Show()

    def load_vault(self):
        self.grid.DeleteAllItems()
        for entry in self.filtered_data:
            index = self.grid.InsertItem(self.grid.GetItemCount(), entry['site'])
            self.grid.SetItem(index, 1, entry['username'])
            self.grid.SetItem(index, 2, entry['password'])

    def save_vault(self):
        data = json.dumps(self.vault_data).encode()
        encrypted = self.fernet.encrypt(data)
        with open(VAULT_FILE, 'wb') as f:
            f.write(self.salt + encrypted)

    def on_add(self, event):
        site = wx.GetTextFromUser("Enter Site", "Add Entry")
        if not site: return
        username = wx.GetTextFromUser("Enter Username", "Add Entry")
        if not username: return
        password = wx.GetTextFromUser("Enter Password", "Add Entry")
        if not password: return

        self.vault_data.append({'site': site, 'username': username, 'password': password})
        self.on_search(None)  # Update filtered_data
        self.save_vault()
        self.load_vault()

    def on_delete(self, event):
        selection = self.grid.GetFirstSelected()
        if selection == -1:
            wx.MessageBox("Select an entry to delete.", "Info")
            return

        item = self.filtered_data[selection]
        self.vault_data.remove(item)
        self.on_search(None)  # Refresh filtered list
        self.save_vault()
        self.load_vault()

    def copy_username(self, event):
        selection = self.grid.GetFirstSelected()
        if selection != -1:
            wx.TheClipboard.Open()
            wx.TheClipboard.SetData(wx.TextDataObject(self.filtered_data[selection]['username']))
            wx.TheClipboard.Close()

    def copy_password(self, event):
        selection = self.grid.GetFirstSelected()
        if selection != -1:
            wx.TheClipboard.Open()
            wx.TheClipboard.SetData(wx.TextDataObject(self.filtered_data[selection]['password']))
            wx.TheClipboard.Close()

    def on_search(self, event):
        query = self.search_ctrl.GetValue().lower()
        self.filtered_data = [entry for entry in self.vault_data if query in entry['site'].lower()]
        self.load_vault()


class MasterPasswordDialog(wx.Dialog):
    def __init__(self):
        super().__init__(None, title="Enter Master Password", size=(300, 150))
        self.password = None

        vbox = wx.BoxSizer(wx.VERTICAL)
        self.txt = wx.TextCtrl(self, style=wx.TE_PASSWORD)
        ok_btn = wx.Button(self, label="OK")

        ok_btn.Bind(wx.EVT_BUTTON, self.on_ok)

        vbox.Add(wx.StaticText(self, label="Master Password:"), flag=wx.ALL, border=10)
        vbox.Add(self.txt, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=10)
        vbox.Add(ok_btn, flag=wx.ALIGN_CENTER | wx.ALL, border=10)

        self.SetSizer(vbox)

    def on_ok(self, event):
        self.password = self.txt.GetValue()
        self.EndModal(wx.ID_OK)

def main():
    app = wx.App(False)
    dlg = MasterPasswordDialog()
    if dlg.ShowModal() == wx.ID_OK:
        master_password = dlg.password
    else:
        dlg.Destroy()
        return
    dlg.Destroy()

    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, 'rb') as f:
            raw = f.read()
        salt = raw[:SALT_SIZE]
        encrypted = raw[SALT_SIZE:]

        key = derive_key(master_password, salt)
        fernet = Fernet(key)

        try:
            decrypted = fernet.decrypt(encrypted)
            vault_data = json.loads(decrypted)
        except (InvalidToken, json.JSONDecodeError):
            wx.MessageBox("Invalid master password or corrupted vault.", "Error", wx.ICON_ERROR)
            return
    else:
        salt = secrets.token_bytes(SALT_SIZE)
        key = derive_key(master_password, salt)
        fernet = Fernet(key)
        vault_data = []

    PasswordManagerApp(None, "Password Manager", vault_data, fernet, salt)
    app.MainLoop()


if __name__ == "__main__":
    main()
