import csv, logging, os, re
from datetime import datetime
import bcrypt
import psycopg2
from dotenv import load_dotenv

# Load environment variables (ensures DATABASE_URL is available)
load_dotenv()

# Safely handle Tkinter for headless server environments (like Render)
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog, filedialog
    TK_OK = True
except ImportError:
    TK_OK = False
    tk = ttk = messagebox = simpledialog = filedialog = None

try:
    from PIL import Image, ImageTk
    PIL_OK = True
except ImportError:
    PIL_OK = False

# ========================= CONFIG =========================
NU_BLUE, NU_YELLOW = '#0033A0', '#FFD100'
LOG_DIR = 'app_logging'
EMAIL_RE = re.compile(r'^[\w.\-]+@[\w.\-]+\.\w+$')
PASSWORD_RE = re.compile(r'^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&*]).{8,}$')

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(filename=os.path.join(LOG_DIR, 'app.log'), level=logging.INFO,
                    format='%(asctime)s - [%(levelname)s] - %(name)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
log = logging.getLogger('HardwareApp')

# ========================= SUPABASE CONNECTION SHIM =========================
class DBConnection:
    """Wrapper to make psycopg2 act like the previous sqlite3 connection workflow."""
    def __init__(self):
        db_url = os.environ.get("DATABASE_URL")
        if not db_url:
            raise ValueError("DATABASE_URL is missing. Please check your .env file.")
        self.conn = psycopg2.connect(db_url)
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.conn.commit()
        else:
            self.conn.rollback()
        self.conn.close()
        
    def execute(self, sql, args=()):
        cur = self.conn.cursor()
        cur.execute(sql, args)
        return cur
        
    def executemany(self, sql, args=()):
        cur = self.conn.cursor()
        cur.executemany(sql, args)
        return cur
        
    def cursor(self):
        return self.conn.cursor()

def db():
    return DBConnection()

def q(sql, args=(), one=False, many=False):
    with db() as c:
        cur = c.execute(sql, args)
        if many: return cur.fetchall()
        return cur.fetchone() if one else None

def exec_sql(sql, args=(), many=False):
    with db() as c:
        if many: c.executemany(sql, args)
        else: c.execute(sql, args)

def status(qty):
    return 'In Stock' if qty > 10 else 'Low Stock' if qty > 0 else 'Out of Stock'

def valid_email(x): return bool(EMAIL_RE.match(x))
def valid_password(x): return bool(PASSWORD_RE.match(x))
def now(): return datetime.now().isoformat(timespec='seconds')
def hashed(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()

def has_col(cur, table, col):
    cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name=%s AND column_name=%s", (table, col))
    return bool(cur.fetchone())

def init_db():
    try:
        with db() as c:
            cur = c.cursor()
            # PostgreSQL uses SERIAL instead of AUTOINCREMENT
            cur.execute('''CREATE TABLE IF NOT EXISTS users(
                id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0, is_locked BOOLEAN DEFAULT FALSE,
                account_status TEXT DEFAULT 'Active')''')
                
            for col, typ in [('account_status', "TEXT DEFAULT 'Active'"),
                             ('failed_attempts', 'INTEGER DEFAULT 0'),
                             ('is_locked', 'BOOLEAN DEFAULT FALSE')]:
                if not has_col(cur, 'users', col):
                    cur.execute(f'ALTER TABLE users ADD COLUMN {col} {typ}')
                    log.info('Migrated users table: added %s.', col)
                    
            cur.execute('''CREATE TABLE IF NOT EXISTS hardware(
                item_id SERIAL PRIMARY KEY, item_name TEXT NOT NULL,
                category TEXT NOT NULL, quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL, status TEXT NOT NULL)''')
                
            cur.execute('''CREATE TABLE IF NOT EXISTS password_resets(
                id SERIAL PRIMARY KEY, username TEXT NOT NULL,
                new_password_hash TEXT NOT NULL, status TEXT DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
                
            cur.execute('''CREATE TABLE IF NOT EXISTS transactions(
                trans_id SERIAL PRIMARY KEY, item_id INTEGER,
                username TEXT, qty INTEGER, timeframe TEXT, status TEXT DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(item_id) REFERENCES hardware(item_id))''')
                
            for table in ('password_resets', 'transactions'):
                if not has_col(cur, table, 'created_at'):
                    cur.execute(f'ALTER TABLE {table} ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
                    log.info('Migrated %s table: added created_at.', table)
                    
            for item_id, qty in c.execute('SELECT item_id, quantity FROM hardware').fetchall():
                c.execute('UPDATE hardware SET status=%s WHERE item_id=%s', (status(qty), item_id))
                
            admin = c.execute("SELECT id FROM users WHERE role='ADMIN' AND account_status='Active' LIMIT 1").fetchone()
            if not admin:
                existing = c.execute("SELECT id FROM users WHERE username='admin' LIMIT 1").fetchone()
                if existing:
                    c.execute("UPDATE users SET account_status='Active',is_locked=FALSE,failed_attempts=0 WHERE id=%s", (existing[0],))
                    log.info('Existing admin account activated.')
                else:
                    c.execute('''INSERT INTO users(username,email,password_hash,role,account_status)
                                   VALUES(%s,%s,%s,%s,%s)''', ('admin','admin@nu.edu.ph',hashed('Admin@123'),'ADMIN','Active'))
                    log.info('Default ADMIN account created (admin / Admin@123).')
    except psycopg2.Error:
        log.exception('Database setup error')
        raise

# ==========================================================
# WEB CONTROLLERS - Pure Python/Database Logic (No Tkinter)
# ==========================================================
class AuthController:
    @staticmethod
    def login_user(username, password):
        try:
            row = q('SELECT password_hash, role, account_status, failed_attempts, is_locked, email FROM users WHERE username=%s', (username,), True)
            if not row: return False, "User not found.", None, False, None
            h, r, st, attempts, locked, email = row
            
            if st == 'Pending': return False, "Account is still pending approval by an Admin.", None, False, None
            if st != 'Active': return False, f"Account is currently '{st}'.", None, False, None
            if locked: return False, "Account locked after 3 failed attempts.", None, True, None

            try: ok = bcrypt.checkpw(password.encode(), h.encode())
            except ValueError: ok = False

            if ok:
                exec_sql('UPDATE users SET failed_attempts=0 WHERE username=%s', (username,))
                log.info("User '%s' logged in successfully via web.", username)
                return True, "Login successful.", r, False, email

            attempts = (attempts or 0) + 1
            if attempts >= 3:
                exec_sql('UPDATE users SET failed_attempts=%s, is_locked=TRUE WHERE username=%s', (attempts, username))
                log.warning("Account '%s' locked due to failed login attempts.", username)
                return False, "Account locked after 3 failed attempts.", None, True, None

            exec_sql('UPDATE users SET failed_attempts=%s WHERE username=%s', (attempts, username))
            return False, f"Invalid password. {3 - attempts} attempt(s) left.", None, False, None
        except psycopg2.Error:
            log.exception('Login DB error')
            return False, "Database error during login.", None, False, None

    @staticmethod
    def register_user(username, email, password, role="USER"):
        if not valid_email(email): return False, "Invalid email format."
        if not valid_password(password): return False, "Password needs 8+ chars, uppercase, number, special char."
        try:
            st = 'Pending' if role == 'ADMIN' else 'Active'
            exec_sql('INSERT INTO users(username, email, password_hash, role, account_status) VALUES(%s,%s,%s,%s,%s)',
                     (username, email, hashed(password), role, st))
            log.info("Registered %s account: %s (status=%s)", role, username, st)
            msg = "Registration submitted. Admin accounts require approval." if role == 'ADMIN' else "Registered successfully."
            return True, msg
        except psycopg2.IntegrityError:
            return False, "Username or Email already exists."
        except psycopg2.Error:
            log.exception('Registration DB error')
            return False, "Database error during registration."

    @staticmethod
    def submit_password_reset_request(username, email, new_password):
        if not valid_password(new_password): return False, "New password needs 8+ chars, uppercase, number, special char."
        try:
            if not q('SELECT id FROM users WHERE username=%s AND email=%s', (username, email), True):
                return False, "Username and Email do not match our records."
            with db() as c:
                c.execute("DELETE FROM password_resets WHERE username=%s AND status='Pending'", (username,))
                c.execute("INSERT INTO password_resets(username, new_password_hash, status, created_at) VALUES(%s,%s,%s,%s)",
                          (username, hashed(new_password), 'Pending', now()))
            log.info("Password reset requested for '%s'.", username)
            return True, "Password reset request submitted for Admin approval."
        except psycopg2.Error:
            log.exception('Reset request DB error')
            return False, "Database error submitting reset request."

    @staticmethod
    def get_pending_resets():
        return q("SELECT id, username, status, created_at FROM password_resets WHERE status='Pending' ORDER BY id", many=True) or []

    @staticmethod
    def get_pending_admins():
        return q("SELECT username, email, account_status FROM users WHERE role='ADMIN' AND account_status='Pending' ORDER BY username", many=True) or []

    @staticmethod
    def approve_admin(usernames):
        if not usernames: return False, "No admins selected."
        count = 0
        try:
            with db() as c:
                for u in usernames:
                    changed = c.execute("UPDATE users SET account_status='Active' WHERE username=%s AND role='ADMIN' AND account_status='Pending'", (u,)).rowcount
                    count += changed
            return True, f"Approved {count} admin account(s)."
        except psycopg2.Error:
            log.exception("Approve admin error")
            return False, "Database error approving admins."

    @staticmethod
    def change_password_direct(username, email, old_password, new_password):
        if not valid_password(new_password): return False, "New password does not meet complexity requirements."
        try:
            row = q('SELECT password_hash FROM users WHERE username=%s', (username,), True)
            if not row or not bcrypt.checkpw(old_password.encode(), row[0].encode()):
                return False, "Incorrect current password."
            exec_sql('UPDATE users SET password_hash=%s, failed_attempts=0, is_locked=FALSE WHERE username=%s',
                     (hashed(new_password), username))
            log.info("User %s changed password via web.", username)
            return True, "Password updated successfully."
        except psycopg2.Error:
            log.exception("Change password DB error")
            return False, "Database error updating password."

    @staticmethod
    def process_bulk_resets(request_ids, approve=True):
        if not request_ids: return False, "No requests selected."
        count = 0
        try:
            with db() as c:
                for rid in request_ids:
                    row = c.execute("SELECT username, new_password_hash FROM password_resets WHERE id=%s AND status='Pending'", (rid,)).fetchone()
                    if row:
                        u, h = row
                        if approve:
                            c.execute("UPDATE users SET password_hash=%s, failed_attempts=0, is_locked=FALSE, account_status='Active' WHERE username=%s", (h, u))
                            c.execute("UPDATE password_resets SET status='Approved' WHERE id=%s", (rid,))
                            log.info("Admin approved reset %s for %s", rid, u)
                        else:
                            c.execute("UPDATE password_resets SET status='Rejected' WHERE id=%s", (rid,))
                            log.info("Admin rejected reset %s for %s", rid, u)
                        count += 1
            return True, f"Processed {count} reset request(s)."
        except psycopg2.Error:
            log.exception("Process reset DB error")
            return False, "Database error processing resets."


class InventoryController:
    @staticmethod
    def get_all_items(search_text="", category="ALL"):
        s = f"%{search_text}%"
        if category == "ALL":
            return q('SELECT item_id, item_name, category, quantity, unit_price, status FROM hardware WHERE item_name LIKE %s OR category LIKE %s ORDER BY item_id', (s, s), many=True) or []
        return q('SELECT item_id, item_name, category, quantity, unit_price, status FROM hardware WHERE (item_name LIKE %s OR category LIKE %s) AND category=%s ORDER BY item_id', (s, s, category), many=True) or []

    @staticmethod
    def get_categories():
        rows = q('SELECT DISTINCT category FROM hardware ORDER BY category', many=True) or []
        return [r[0] for r in rows]

    @staticmethod
    def get_user_active_loans(username):
        return q("SELECT trans_id, item_id, qty, timeframe, status, created_at FROM transactions WHERE username=%s AND status='Approved' ORDER BY trans_id DESC", (username,), many=True) or []

    @staticmethod
    def get_user_pending_borrows(username):
        return q("SELECT trans_id, item_id, qty, timeframe, status, created_at FROM transactions WHERE username=%s AND status='Pending' ORDER BY trans_id DESC", (username,), many=True) or []

    @staticmethod
    def get_user_loan_history(username):
        return q("SELECT trans_id, item_id, qty, timeframe, status, created_at FROM transactions WHERE username=%s ORDER BY trans_id DESC", (username,), many=True) or []

    @staticmethod
    def get_pending_returns():
        return q("SELECT trans_id, username, item_id, qty, timeframe, status FROM transactions WHERE status='Returned' ORDER BY trans_id", many=True) or []

    @staticmethod
    def get_pending_borrows():
        return q("SELECT trans_id, username, item_id, qty, timeframe, status FROM transactions WHERE status='Pending' ORDER BY trans_id", many=True) or []

    @staticmethod
    def get_all_loans_history():
        return q("SELECT trans_id, username, item_id, qty, timeframe, status FROM transactions ORDER BY trans_id DESC", many=True) or []

    @staticmethod
    def borrow_item(username, item_id, quantity):
        try:
            with db() as c:
                current = c.execute('SELECT item_name, quantity FROM hardware WHERE item_id=%s', (item_id,)).fetchone()
                if not current: return False, "Hardware item no longer exists."
                name, available = current
                if quantity > available: return False, f"Only {available} unit(s) of '{name}' are currently available."
                c.execute("INSERT INTO transactions(item_id, username, qty, timeframe, status, created_at) VALUES(%s,%s,%s,%s,%s,%s)",
                          (item_id, username, quantity, "Web Request", 'Pending', now()))
            log.info("User %s requested to borrow %s of item %s.", username, quantity, item_id)
            return True, "Borrow request submitted for Admin approval."
        except psycopg2.Error:
            log.exception("Borrow request DB error")
            return False, "Database error submitting borrow request."

    @staticmethod
    def request_bulk_item_returns(loan_ids):
        if not loan_ids: return False, "No items selected."
        count = 0
        try:
            with db() as c:
                for tid in loan_ids:
                    changed = c.execute("UPDATE transactions SET status='Returned' WHERE trans_id=%s AND status='Approved'", (tid,)).rowcount
                    count += changed
            log.info("Flagged %s transactions as returned.", count)
            return True, f"Requested return for {count} item(s)."
        except psycopg2.Error:
            log.exception("Return request DB error")
            return False, "Database error requesting return."

    @staticmethod
    def save_item(item_id, name, category, quantity, unit_price):
        if not name or not category: return False, "Name and Category are required."
        try:
            with db() as c:
                if item_id:
                    c.execute('UPDATE hardware SET item_name=%s, category=%s, quantity=%s, unit_price=%s, status=%s WHERE item_id=%s',
                              (name, category, quantity, unit_price, status(quantity), item_id))
                    log.info("Updated item ID %s.", item_id)
                    return True, "Hardware item updated successfully."
                else:
                    c.execute('INSERT INTO hardware(item_name, category, quantity, unit_price, status) VALUES(%s,%s,%s,%s,%s)',
                              (name, category, quantity, unit_price, status(quantity)))
                    log.info("Added inventory item '%s'.", name)
                    return True, "Hardware item added successfully."
        except psycopg2.Error:
            log.exception("Save item DB error")
            return False, "Database error saving item."

    @staticmethod
    def delete_bulk_items(item_ids):
        if not item_ids: return False, "No items selected."
        count = 0
        try:
            with db() as c:
                for iid in item_ids:
                    if c.execute('SELECT COUNT(*) FROM transactions WHERE item_id=%s', (iid,)).fetchone()[0]:
                        continue
                    c.execute('DELETE FROM hardware WHERE item_id=%s', (iid,))
                    count += 1
            return True, f"Deleted {count} hardware item(s)."
        except psycopg2.Error:
            log.exception("Delete items DB error")
            return False, "Database error deleting items."

    @staticmethod
    def process_bulk_borrows(loan_ids, approve=True):
        if not loan_ids: return False, "No requests selected."
        count = 0
        try:
            with db() as c:
                for tid in loan_ids:
                    req = c.execute("SELECT item_id, qty, username FROM transactions WHERE trans_id=%s AND status='Pending'", (tid,)).fetchone()
                    if not req: continue
                    item_id, qty, u = req
                    
                    if approve:
                        hw = c.execute("SELECT quantity FROM hardware WHERE item_id=%s", (item_id,)).fetchone()
                        if hw and hw[0] >= qty:
                            new_qty = hw[0] - qty
                            c.execute("UPDATE hardware SET quantity=%s, status=%s WHERE item_id=%s", (new_qty, status(new_qty), item_id))
                            c.execute("UPDATE transactions SET status='Approved' WHERE trans_id=%s", (tid,))
                            count += 1
                    else:
                        c.execute("UPDATE transactions SET status='Rejected' WHERE trans_id=%s", (tid,))
                        count += 1
            return True, f"Processed {count} borrow request(s)."
        except psycopg2.Error:
            log.exception("Process borrow DB error")
            return False, "Database error processing borrows."

    @staticmethod
    def process_bulk_returns(loan_ids, approve=True):
        if not loan_ids: return False, "No requests selected."
        count = 0
        try:
            with db() as c:
                for tid in loan_ids:
                    req = c.execute("SELECT item_id, qty FROM transactions WHERE trans_id=%s AND status='Returned'", (tid,)).fetchone()
                    if not req: continue
                    item_id, qty = req
                    
                    if approve:
                        hw = c.execute("SELECT quantity FROM hardware WHERE item_id=%s", (item_id,)).fetchone()
                        if hw:
                            new_qty = hw[0] + qty
                            c.execute("UPDATE hardware SET quantity=%s, status=%s WHERE item_id=%s", (new_qty, status(new_qty), item_id))
                            c.execute("UPDATE transactions SET status='Completed' WHERE trans_id=%s", (tid,))
                            count += 1
                    else:
                        c.execute("UPDATE transactions SET status='Approved' WHERE trans_id=%s", (tid,))
                        count += 1
            return True, f"Processed {count} return request(s)."
        except psycopg2.Error:
            log.exception("Process return DB error")
            return False, "Database error processing returns."

    @staticmethod
    def export_to_csv(username):
        try:
            rows = q('SELECT item_id, item_name, category, quantity, unit_price, status FROM hardware ORDER BY item_id', many=True)
            path = os.path.abspath('inventory_report.csv')
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                csv.writer(f).writerows([['ID', 'Name', 'Category', 'Qty', 'Price', 'Status'], *rows])
            log.info("User %s exported web CSV.", username)
            return True, "Export successful."
        except Exception:
            log.exception("CSV export error")
            return False, "Error creating CSV."

# ========================= SMALL UI HELPERS =========================
def clear(parent):
    for w in parent.winfo_children(): w.destroy()


def tree(parent, columns, widths, height=None, select='browse'):
    t = ttk.Treeview(parent, columns=columns, show='headings', selectmode=select, **({'height': height} if height else {}))
    for col in columns:
        t.heading(col, text=col); t.column(col, width=widths.get(col, 110), anchor='center')
    return t


def fill_tree(t, rows):
    t.delete(*t.get_children())
    for row in rows: t.insert('', tk.END, values=row)


def button(parent, text, command, **kw):
    return tk.Button(parent, text=text, command=command, **kw)


# ==========================================================
# DESKTOP ONLY — retained for the original desktop version
# Do not call these classes from the Flask web application.
# ==========================================================

# ========================= AUTH =========================
class AuthWindow:
    def __init__(self, root, success):
        self.root, self.success = root, success
        root.geometry('450x700'); root.minsize(450,600); root.resizable(False,False); root.config(bg=NU_BLUE)
        self.main = tk.Frame(root, bg=NU_BLUE); self.main.pack(fill='both', expand=True, pady=10)
        self.login_screen()

    def label(self, text, **kw):
        d = dict(bg=NU_BLUE, fg='white'); d.update(kw); return tk.Label(self.main, text=text, **d)

    def logo(self):
        if PIL_OK and os.path.exists('nu_logo.png'):
            try:
                im = Image.open('nu_logo.png'); im.thumbnail((210,255)); self.logo_img = ImageTk.PhotoImage(im)
                tk.Label(self.main, image=self.logo_img, bg=NU_BLUE).pack(pady=5)
            except Exception as e: log.error('Image load error: %s', e)

    def field(self, label, show=None):
        self.label(label).pack(); e = tk.Entry(self.main, width=30, show=show or '') ; e.pack(pady=2); return e

    def login_screen(self):
        clear(self.main); self.root.title('National University Laboratory Inventory System'); self.logo()
        self.label('National University\nLaboratory Inventory System', font=('Arial',14,'bold'), fg=NU_YELLOW).pack(pady=8)
        self.e_user = self.field('Username:'); self.e_pass = self.field('Password:', '*')
        button(self.main,'Login',self.login,width=20,bg=NU_YELLOW,fg=NU_BLUE,font=('Arial',10,'bold')).pack(pady=10)
        button(self.main,'Register Account',self.register_screen,width=20).pack(pady=2)
        button(self.main,'Locked Out? Request Password Reset',self.reset_screen,width=28,fg='red').pack(pady=6)
        self.e_user.focus_set()

    def register_screen(self):
        clear(self.main); self.root.title('Register Account')
        self.label('Create Account',font=('Arial',16,'bold'),fg=NU_YELLOW).pack(pady=10)
        self.r_user=self.field('Username:'); self.r_email=self.field('Email:'); self.r_pass=self.field('Password:','*')
        self.label('Role:').pack(); self.role=tk.StringVar(value='USER')
        ttk.Combobox(self.main,textvariable=self.role,values=['USER','ADMIN'],state='readonly',width=27).pack(pady=2)
        self.label('Password: 8+ chars, uppercase, number, special character.',fg='#D9E4FF').pack(pady=5)
        button(self.main,'Register',self.register,width=15,bg=NU_YELLOW,fg=NU_BLUE,font=('Arial',10,'bold')).pack(pady=15)
        button(self.main,'Back',self.login_screen,width=15).pack()

    def reset_screen(self):
        clear(self.main); self.root.title('Request Password Reset')
        self.label('Request Password Reset',font=('Arial',14,'bold'),fg=NU_YELLOW).pack(pady=10)
        self.label('An Admin must approve the reset before the account is unlocked.',fg='#D9E4FF').pack(pady=5)
        self.e_res_user=self.field('Username:'); self.e_res_email=self.field('Registered Email:'); self.e_res_pass=self.field('New Password:','*')
        button(self.main,'Submit Reset Request',self.submit_reset,width=22,bg=NU_YELLOW,fg=NU_BLUE,font=('Arial',10,'bold')).pack(pady=15)
        button(self.main,'Back to Login',self.login_screen,width=15).pack()

    def register(self):
        u,e,p,r=self.r_user.get().strip(),self.r_email.get().strip(),self.r_pass.get().strip(),self.role.get().strip()
        if not u or not e or not p: return messagebox.showwarning('Error','All fields are required.')
        if not valid_email(e): return messagebox.showwarning('Error','Invalid email format.')
        if not valid_password(p): return messagebox.showwarning('Error','Password needs 8+ characters, 1 uppercase, 1 number, and 1 special character (@#$%^&*).')
        try:
            exec_sql('INSERT INTO users(username,email,password_hash,role,account_status) VALUES(%s,%s,%s,%s,%s)',(u,e,hashed(p),r,'Pending' if r=='ADMIN' else 'Active'))
            st='Pending' if r=='ADMIN' else 'Active'; log.info('Registered %s account: %s (status=%s)',r,u,st)
            messagebox.showinfo('Success','Registration submitted. Admin accounts require approval before they can log in.' if r=='ADMIN' else 'Registered successfully.')
            self.login_screen()
        except psycopg2.IntegrityError: messagebox.showerror('Error','Username or Email already exists.')
        except psycopg2.Error:
            log.exception('Registration database error'); messagebox.showerror('Database Error','Unable to register account.')

    def login(self):
        u,p=self.e_user.get().strip(),self.e_pass.get()
        if not u or not p: return messagebox.showwarning('Error','Fields cannot be blank.')
        try:
            row=q('SELECT password_hash,role,account_status,failed_attempts,is_locked FROM users WHERE username=%s',(u,),True)
            if not row: return messagebox.showerror('Error','User not found.')
            h,r,st,attempts,locked=row
            if st=='Pending': return messagebox.showwarning('Pending','This account is still pending approval by an Admin.')
            if st!='Active': return messagebox.showerror('Account Unavailable',f"This account is currently '{st}'.")
            if locked: return messagebox.showerror('Locked','Account locked after 3 failed attempts. Use the password reset request.')
            try: ok=bcrypt.checkpw(p.encode(),h.encode())
            except ValueError: ok=False
            if ok:
                exec_sql('UPDATE users SET failed_attempts=0 WHERE username=%s',(u,)); log.info("User '%s' logged in successfully.",u); return self.success(u,r)
            attempts=(attempts or 0)+1
            if attempts>=3:
                exec_sql('UPDATE users SET failed_attempts=%s,is_locked=TRUE WHERE username=%s',(attempts,u)); msg='Account locked after 3 failed attempts. Request a password reset.'; log.warning("Account '%s' locked due to failed login attempts.",u)
            else:
                exec_sql('UPDATE users SET failed_attempts=%s WHERE username=%s',(attempts,u)); msg=f'Invalid password. {3-attempts} attempt(s) left.'
            messagebox.showerror('Login Failed',msg)
        except psycopg2.Error:
            log.exception('Login database error'); messagebox.showerror('Database Error','Unable to complete login.')

    def submit_reset(self):
        u,e,p=self.e_res_user.get().strip(),self.e_res_email.get().strip(),self.e_res_pass.get().strip()
        if not u or not e or not p: return messagebox.showwarning('Error','All fields are required.')
        if not valid_password(p): return messagebox.showwarning('Error','New password needs 8+ characters, 1 uppercase, 1 number, and 1 special character.')
        try:
            if not q('SELECT id FROM users WHERE username=%s AND email=%s',(u,e),True): return messagebox.showerror('Error','Username and Email do not match our records.')
            with db() as c:
                c.execute("DELETE FROM password_resets WHERE username=%s AND status='Pending'",(u,))
                c.execute("INSERT INTO password_resets(username,new_password_hash,status,created_at) VALUES(%s,%s,%s,%s)",(u,hashed(p),'Pending',now()))
            log.info("Password reset requested for '%s'.",u); messagebox.showinfo('Success','Password reset request submitted for Admin approval.'); self.login_screen()
        except psycopg2.Error:
            log.exception('Password reset request error'); messagebox.showerror('Database Error','Unable to submit password reset request.')


# ========================= MAIN APP =========================
class App:
    def __init__(self, root, username, role, logout):
        self.root,self.username,self.role,self.logout_cb=root,username,role,logout
        root.title(f'NU Lab Inventory | {role}: {username}'); root.geometry('1100x780'); root.minsize(950,650); root.config(bg='white')
        self.header(); self.nb=ttk.Notebook(root); self.nb.pack(fill='both',expand=True,padx=10,pady=(0,10))
        self.inventory_tab(); self.borrow_tab(); self.profile_tab()
        if role=='ADMIN': self.admin_tab()

    def header(self):
        h=tk.Frame(self.root,bg=NU_BLUE,pady=10); h.pack(fill='x')
        tk.Label(h,text=f'NU Lab Inventory | {self.role}: {self.username}',bg=NU_BLUE,fg=NU_YELLOW,font=('Arial',14,'bold')).pack(side='left',padx=10)
        button(h,'Logout',self.logout,bg='red',fg='white',width=10).pack(side='right',padx=10)

    def inventory_tab(self):
        self.inv=tk.Frame(self.nb); self.nb.add(self.inv,text='Hardware Catalog')
        c=tk.Frame(self.inv,pady=7); c.pack(fill='x',padx=5)
        tk.Label(c,text='Search:').pack(side='left',padx=(0,5)); self.search=tk.Entry(c,width=28); self.search.pack(side='left',padx=5)
        button(c,'Filter',self.load_inventory).pack(side='left',padx=2); button(c,'Clear',self.clear_inventory).pack(side='left',padx=2); button(c,'Refresh',self.load_inventory).pack(side='left',padx=2)
        button(c,'Export CSV',self.export_csv).pack(side='right',padx=5); button(c,'Request Borrow (Multi-Select)',self.borrow_request,bg=NU_BLUE,fg='white').pack(side='right',padx=5)
        if self.role=='ADMIN': self.inventory_form()
        self.tree=tree(self.inv,('ID','Name','Category','Qty','Price','Status'),{'ID':70,'Name':240,'Category':170,'Qty':90,'Price':110,'Status':130},select='extended')
        sb=ttk.Scrollbar(self.inv,orient='vertical',command=self.tree.yview); self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side='left',fill='both',expand=True,pady=10,padx=(5,0)); sb.pack(side='right',fill='y',pady=10,padx=(0,5))
        if self.role=='ADMIN': self.tree.bind('<ButtonRelease-1>',self.select_item)
        self.load_inventory()

    def inventory_form(self):
        f=tk.LabelFrame(self.inv,text='Manage Component (Admin Only)',padx=10,pady=7); f.pack(fill='x',padx=5,pady=5); self.sel=tk.StringVar()
        self.i_name=self.form_entry(f,'Name:',0,0); self.i_cat=self.form_entry(f,'Category:',0,2); self.i_qty=self.form_entry(f,'Quantity:',1,0); self.i_price=self.form_entry(f,'Price:',1,2)
        button(f,'Save/Update',self.save_item,bg='green',fg='white',width=14).grid(row=1,column=4,padx=10); button(f,'Delete Item',self.delete_item,bg='red',fg='white',width=14).grid(row=1,column=5,padx=5); button(f,'Clear Inputs',self.clear_inventory,width=14).grid(row=0,column=4,padx=10)

    @staticmethod
    def form_entry(parent,label,row,col):
        tk.Label(parent,text=label).grid(row=row,column=col,sticky='e',padx=4,pady=3); e=tk.Entry(parent,width=22); e.grid(row=row,column=col+1,padx=5,pady=3); return e

    def load_inventory(self):
        if not hasattr(self,'tree'): return
        s=f'%{self.search.get().strip()}%'
        try: fill_tree(self.tree,q('SELECT item_id,item_name,category,quantity,unit_price,status FROM hardware WHERE item_name LIKE %s OR category LIKE %s ORDER BY item_id',(s,s),many=True))
        except psycopg2.Error:
            log.exception('Inventory load error'); messagebox.showerror('Database Error','Unable to load inventory.')

    def clear_inventory(self):
        if self.role=='ADMIN':
            self.sel.set('')
            for e in (self.i_name,self.i_cat,self.i_qty,self.i_price): e.delete(0,tk.END)
        self.search.delete(0,tk.END); self.load_inventory()

    def select_item(self,event=None):
        item=self.tree.focus()
        if not item: return
        v=self.tree.item(item,'values'); self.sel.set(v[0])
        for e,x in zip((self.i_name,self.i_cat,self.i_qty,self.i_price),v[1:5]): e.delete(0,tk.END); e.insert(0,x)

    def save_item(self):
        name,cat=self.i_name.get().strip(),self.i_cat.get().strip()
        if not name or not cat: return messagebox.showwarning('Error','Name and Category are required.')
        try:
            qty=int(self.i_qty.get().strip()); price=float(self.i_price.get().strip())
            if qty<0 or price<0: raise ValueError
        except ValueError: return messagebox.showerror('Error','Quantity must be a non-negative integer and Price must be a non-negative number.')
        try:
            with db() as c:
                if self.sel.get(): c.execute('UPDATE hardware SET item_name=%s,category=%s,quantity=%s,unit_price=%s,status=%s WHERE item_id=%s',(name,cat,qty,price,status(qty),self.sel.get())); action=f'updated item ID {self.sel.get()}'
                else: c.execute('INSERT INTO hardware(item_name,category,quantity,unit_price,status) VALUES(%s,%s,%s,%s,%s)',(name,cat,qty,price,status(qty))); action=f"added inventory item '{name}'"
            log.info('ADMIN %s %s.',self.username,action); self.clear_inventory(); messagebox.showinfo('Success','Hardware item saved successfully.')
        except psycopg2.Error:
            log.exception('Save inventory error'); messagebox.showerror('Database Error','Unable to save the hardware item.')

    def delete_item(self):
        item=self.sel.get()
        if not item: return messagebox.showwarning('Notice','Select an item from the table to delete.')
        if not messagebox.askyesno('Confirm','Are you sure you want to delete this hardware item?'): return
        try:
            with db() as c:
                if c.execute('SELECT COUNT(*) FROM transactions WHERE item_id=%s',(item,)).fetchone()[0]: return messagebox.showwarning('Cannot Delete','This item has transaction history and cannot be deleted. Keep it in the catalog for record integrity.')
                c.execute('DELETE FROM hardware WHERE item_id=%s',(item,))
            log.info('ADMIN %s deleted item ID %s.',self.username,item); self.clear_inventory(); messagebox.showinfo('Success','Hardware item deleted.')
        except psycopg2.Error:
            log.exception('Delete inventory error'); messagebox.showerror('Database Error','Unable to delete the hardware item.')

    def export_csv(self):
        try:
            rows=q('SELECT item_id,item_name,category,quantity,unit_price,status FROM hardware ORDER BY item_id',many=True)
            path=filedialog.asksaveasfilename(title='Export Inventory',defaultextension='.csv',initialfile='inventory_export.csv',filetypes=[('CSV files','*.csv'),('All files','*.*')])
            if not path:return
            with open(path,'w',newline='',encoding='utf-8-sig') as f: csv.writer(f).writerows([['ID','Name','Category','Qty','Price','Status'],*rows])
            log.info('User %s exported inventory CSV to %s.',self.username,path); messagebox.showinfo('Success',f'Inventory exported successfully to:\n{path}')
        except (OSError,psycopg2.Error): log.exception('CSV export error'); messagebox.showerror('Export Error','Unable to export the inventory.')

    # ---------------- BORROW / RETURN ----------------
    def borrow_request(self):
        selected=self.tree.selection()
        if not selected:return messagebox.showinfo('Notice','Select one or more items using Ctrl+Click.')
        tf=simpledialog.askstring('Timeframe','Enter timeframe (e.g. Sept 3 - Sept 5):',parent=self.root)
        if not tf or not tf.strip():return
        made=0
        try:
            with db() as c:
                for iid in selected:
                    v=self.tree.item(iid,'values'); item_id,name,_,available,_,_=v; available=int(available)
                    if available<=0: messagebox.showwarning('Unavailable',f"'{name}' is currently out of stock."); continue
                    qty=simpledialog.askinteger('Quantity',f"How many '{name}' do you want to borrow?\nAvailable: {available}",minvalue=1,maxvalue=available,parent=self.root)
                    if qty is None:continue
                    current=c.execute('SELECT quantity FROM hardware WHERE item_id=%s',(item_id,)).fetchone()
                    if not current: messagebox.showwarning('Unavailable',f"'{name}' no longer exists."); continue
                    if qty>int(current[0]): messagebox.showwarning('Unavailable',f"Only {current[0]} unit(s) of '{name}' are currently available."); continue
                    c.execute("INSERT INTO transactions(item_id,username,qty,timeframe,status,created_at) VALUES(%s,%s,%s,%s,%s,%s)",(item_id,self.username,qty,tf.strip(),'Pending',now())); made+=1
            if made: log.info('User %s submitted %d borrow request(s).',self.username,made); messagebox.showinfo('Success',f'{made} borrow request(s) submitted for Admin approval.')
            self.load_borrowed()
        except psycopg2.Error: log.exception('Borrow request error'); messagebox.showerror('Database Error','Unable to submit borrow request(s).')

    def borrow_tab(self):
        self.btab=tk.Frame(self.nb); self.nb.add(self.btab,text='My Borrowed Items'); c=tk.Frame(self.btab,pady=7); c.pack(fill='x')
        button(c,'Refresh',self.load_borrowed).pack(side='left',padx=5); button(c,'Return Selected',self.return_items,bg=NU_YELLOW,fg=NU_BLUE).pack(side='left',padx=5)
        self.btree=tree(self.btab,('TransID','ItemID','Qty','Timeframe','Status','Requested'),{'TransID':80,'ItemID':80,'Qty':70,'Timeframe':180,'Status':120,'Requested':170},select='extended'); self.btree.pack(fill='both',expand=True,padx=5,pady=10); self.load_borrowed()

    def load_borrowed(self):
        if not hasattr(self,'btree'):return
        try: fill_tree(self.btree,q('SELECT trans_id,item_id,qty,timeframe,status,created_at FROM transactions WHERE username=%s ORDER BY trans_id DESC',(self.username,),many=True))
        except psycopg2.Error: log.exception('Borrowed-items load error'); messagebox.showerror('Database Error','Unable to load your borrowing history.')

    def return_items(self):
        ids=[]
        for x in self.btree.selection():
            v=self.btree.item(x,'values')
            if v[4]=='Approved': ids.append(v[0])
        if not ids:return messagebox.showinfo('Notice',"Only transactions with status 'Approved' can be returned.")
        try:
            with db() as c:
                for tid in ids:c.execute("UPDATE transactions SET status='Returned' WHERE trans_id=%s AND username=%s AND status='Approved'",(tid,self.username))
            log.info('User %s flagged %d transaction(s) as returned.',self.username,len(ids)); self.load_borrowed(); self.refresh_admin_views() if self.role=='ADMIN' else None; messagebox.showinfo('Success','Selected item(s) flagged as returned. Awaiting Admin confirmation.')
        except psycopg2.Error: log.exception('Return request error'); messagebox.showerror('Database Error','Unable to process the return.')

    # ---------------- PROFILE ----------------
    def profile_tab(self):
        self.ptab=tk.Frame(self.nb,padx=25,pady=20); self.nb.add(self.ptab,text='My Profile & Security')
        a=tk.LabelFrame(self.ptab,text='Account Details',padx=15,pady=15); a.pack(fill='x',pady=(0,15)); row=q('SELECT email,account_status FROM users WHERE username=%s',(self.username,),True) or ('Unknown','Unknown')
        for text in (f'Username: {self.username}',f'Email: {row[0]}',f'Role Assigned: {self.role}',f'Account Status: {row[1]}'): tk.Label(a,text=text,font=('Arial',11)).pack(anchor='w',pady=2)
        s=tk.LabelFrame(self.ptab,text='Change Password',padx=15,pady=15); s.pack(fill='x',pady=5); tk.Label(s,text='New Password:').pack(anchor='w'); self.newpass=tk.Entry(s,show='*',width=35); self.newpass.pack(anchor='w',pady=5); tk.Label(s,text='8+ characters, uppercase letter, number, special character.').pack(anchor='w',pady=(0,8)); button(s,'Update Password',self.change_password).pack(anchor='w')

    def change_password(self):
        p=self.newpass.get().strip()
        if not valid_password(p):return messagebox.showerror('Error','Password needs 8+ characters, 1 uppercase, 1 number, and 1 special character (@#$%^&*).')
        try:
            exec_sql('UPDATE users SET password_hash=%s,failed_attempts=0,is_locked=FALSE WHERE username=%s',(hashed(p),self.username)); log.info('User %s changed their password.',self.username); messagebox.showinfo('Success','Password updated successfully. Please log in again.'); self.logout()
        except psycopg2.Error: log.exception('Change password error'); messagebox.showerror('Database Error','Unable to update the password.')

    # ---------------- ADMIN ----------------
    def admin_tab(self):
        self.atab=tk.Frame(self.nb,padx=8,pady=8); self.nb.add(self.atab,text='Admin Panel'); button(self.atab,'Refresh All Admin Data',self.refresh_admin_views,bg=NU_YELLOW,fg=NU_BLUE,font=('Arial',10,'bold')).pack(anchor='w',pady=5)
        tk.Label(self.atab,text='Pending Admin Registrations',font=('Arial',12,'bold')).pack(pady=(6,2)); self.atree=tree(self.atab,('User','Email','Status'),{'User':180,'Email':300,'Status':120},4); self.atree.pack(fill='x',pady=5); button(self.atab,'Approve Admin',self.approve_admin,bg='green',fg='white').pack(pady=(0,8))
        tk.Label(self.atab,text='Pending Password Reset Requests',font=('Arial',12,'bold')).pack(pady=(6,2)); self.rtree=tree(self.atab,('RequestID','User','Status','Created'),{'RequestID':90,'User':180,'Status':120,'Created':220},5); self.rtree.pack(fill='x',pady=5); f=tk.Frame(self.atab); f.pack(pady=3); button(f,'Approve Reset',self.approve_reset,bg='green',fg='white').pack(side='left',padx=5); button(f,'Reject Reset',self.reject_reset,bg='red',fg='white').pack(side='left',padx=5)
        tk.Label(self.atab,text='Transaction Management (Borrows & Returns)',font=('Arial',12,'bold')).pack(pady=(12,2)); self.ttree=tree(self.atab,('TransID','User','ItemID','Qty','Timeframe','Status'),{'TransID':80,'User':150,'ItemID':80,'Qty':70,'Timeframe':200,'Status':120}); self.ttree.pack(fill='both',expand=True,pady=5); f=tk.Frame(self.atab); f.pack(pady=5); button(f,'Approve Borrow',self.approve_borrow,bg='green',fg='white').pack(side='left',padx=5); button(f,'Confirm Return',self.confirm_return,bg=NU_BLUE,fg='white').pack(side='left',padx=5); self.refresh_admin_views()

    def refresh_admin_views(self):
        if not hasattr(self,'atree'):return
        try:
            fill_tree(self.atree,q("SELECT username,email,account_status FROM users WHERE role='ADMIN' AND account_status='Pending' ORDER BY username",many=True))
            fill_tree(self.rtree,q("SELECT id,username,status,created_at FROM password_resets WHERE status='Pending' ORDER BY id",many=True))
            fill_tree(self.ttree,q("SELECT trans_id,username,item_id,qty,timeframe,status FROM transactions WHERE status IN ('Pending','Returned') ORDER BY trans_id",many=True))
        except psycopg2.Error: log.exception('Admin refresh error'); messagebox.showerror('Database Error','Unable to refresh Admin data.')

    def approve_admin(self):
        s=self.atree.selection()
        if not s:return messagebox.showinfo('Notice','Select a pending admin registration.')
        u=self.atree.item(s[0],'values')[0]
        try:
            with db() as c: changed=c.execute("UPDATE users SET account_status='Active' WHERE username=%s AND role='ADMIN' AND account_status='Pending'",(u,)).rowcount
            if changed: log.info("ADMIN %s approved admin account '%s'.",self.username,u); messagebox.showinfo('Approved',f"Admin account '{u}' is now active.")
            self.refresh_admin_views()
        except psycopg2.Error: log.exception('Approve admin error'); messagebox.showerror('Database Error','Unable to approve the admin account.')

    def reset_selected(self):
        s=self.rtree.selection()
        return (self.rtree.item(s[0],'values')[0],self.rtree.item(s[0],'values')[1]) if s else (None,None)

    def approve_reset(self):
        rid,u=self.reset_selected()
        if not rid:return messagebox.showinfo('Notice','Select a pending password reset request.')
        try:
            with db() as c:
                row=c.execute("SELECT new_password_hash FROM password_resets WHERE id=%s AND status='Pending'",(rid,)).fetchone()
                if not row:return messagebox.showwarning('Notice','That reset request is no longer pending.')
                c.execute("UPDATE users SET password_hash=%s,failed_attempts=0,is_locked=FALSE,account_status='Active' WHERE username=%s",(row[0],u)); c.execute("UPDATE password_resets SET status='Approved' WHERE id=%s",(rid,))
            log.info("ADMIN %s approved reset request %s for '%s'.",self.username,rid,u); messagebox.showinfo('Approved',f"Account '{u}' unlocked with the new password."); self.refresh_admin_views()
        except psycopg2.Error: log.exception('Approve reset error'); messagebox.showerror('Database Error','Unable to approve the password reset.')

    def reject_reset(self):
        rid,u=self.reset_selected()
        if not rid:return messagebox.showinfo('Notice','Select a pending password reset request.')
        if not messagebox.askyesno('Confirm Rejection',f"Reject the password reset request for '{u}'?"):return
        try:
            exec_sql("UPDATE password_resets SET status='Rejected' WHERE id=%s AND status='Pending'",(rid,)); log.info("ADMIN %s rejected reset request %s for '%s'.",self.username,rid,u); self.refresh_admin_views()
        except psycopg2.Error: log.exception('Reject reset error'); messagebox.showerror('Database Error','Unable to reject the password reset.')

    def transaction_selected(self):
        s=self.ttree.selection(); return self.ttree.item(s[0],'values') if s else None

    def approve_borrow(self):
        v=self.transaction_selected()
        if not v:return messagebox.showinfo('Notice','Select a pending borrow transaction.')
        tid,u,item,qty,tf,st=v
        if st!='Pending':return messagebox.showwarning('Notice','Only Pending borrow requests can be approved.')
        try:
            with db() as c:
                row=c.execute('SELECT item_name,quantity FROM hardware WHERE item_id=%s',(item,)).fetchone()
                if not row:return messagebox.showerror('Error','The requested hardware item no longer exists.')
                name,current=row; qty=int(qty)
                if qty<=0 or qty>current:return messagebox.showwarning('Insufficient Stock',f"Cannot approve this request for '{name}'. Current available quantity: {current}.")
                new=current-qty; c.execute('UPDATE hardware SET quantity=%s,status=%s WHERE item_id=%s',(new,status(new),item)); changed=c.execute("UPDATE transactions SET status='Approved' WHERE trans_id=%s AND status='Pending'",(tid,)).rowcount
            if changed:
                log.info('ADMIN %s approved borrow transaction %s for %s unit(s) of item %s for user %s.',self.username,tid,qty,item,u); self.refresh_admin_views(); self.load_inventory(); self.load_borrowed(); messagebox.showinfo('Approved',f'Borrow request #{tid} approved for {u}.')
        except psycopg2.Error: log.exception('Approve borrow error'); messagebox.showerror('Database Error','Unable to approve the borrow request.')

    def confirm_return(self):
        v=self.transaction_selected()
        if not v:return messagebox.showinfo('Notice','Select a returned transaction.')
        tid,u,item,qty,tf,st=v
        if st!='Returned':return messagebox.showwarning('Notice','Only transactions marked Returned can be confirmed.')
        try:
            with db() as c:
                row=c.execute('SELECT item_name,quantity FROM hardware WHERE item_id=%s',(item,)).fetchone()
                if not row:return messagebox.showerror('Error','The original hardware item no longer exists.')
                name,current=row; qty=int(qty); c.execute('UPDATE hardware SET quantity=%s,status=%s WHERE item_id=%s',(current+qty,status(current+qty),item)); c.execute("UPDATE transactions SET status='Completed' WHERE trans_id=%s AND status='Returned'",(tid,))
            log.info('ADMIN %s confirmed return for transaction %s (%s unit(s) of %s).',self.username,tid,qty,name); self.refresh_admin_views(); self.load_inventory(); self.load_borrowed(); messagebox.showinfo('Success','Return confirmed and inventory quantity restored.')
        except psycopg2.Error: log.exception('Confirm return error'); messagebox.showerror('Database Error','Unable to confirm the return.')

    def logout(self):
        log.info('User %s logged out.',self.username); self.logout_cb()


# ========================= CONTROLLER =========================
class Controller:
    def __init__(self):
        init_db(); self.root=tk.Tk(); self.root.protocol('WM_DELETE_WINDOW',self.close); self.auth(); self.root.mainloop()
    def clear(self): clear(self.root)
    def auth(self): self.clear(); AuthWindow(self.root,self.app)
    def app(self,u,r): self.clear(); App(self.root,u,r,self.auth)
    def close(self): log.info('Application closed.'); self.root.destroy()


if __name__=='__main__': Controller()