from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import mimetypes
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt
from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / 'data'
UPLOAD_DIR = DATA_DIR / 'uploads'
DB_PATH = DATA_DIR / 'club.db'
FRONTEND_DIR = BASE_DIR / 'frontend'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.getenv('CLUB_SECRET_KEY', 'CHANGE-ME-IN-PRODUCTION-alyat-police-v5')
JWT_ALGORITHM = 'HS256'
TOKEN_HOURS = int(os.getenv('TOKEN_HOURS', '12'))
PBKDF2_ITERATIONS = 260_000
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_MB', '100')) * 1024 * 1024
ALLOWED_EXTENSIONS = {'.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.jpg','.jpeg','.png','.webp','.mp4','.mov','.avi','.zip'}

PERMISSIONS = {
    'dashboard.view':'مشاهدة لوحة التحكم',
    'notices.view':'مشاهدة التبليغات','notices.create':'نشر التبليغات','notices.delete':'حذف التبليغات',
    'records.view':'مشاهدة الكتب والمعاملات','records.create':'إضافة الكتب والمعاملات','records.update':'تعديل الكتب والمعاملات','records.approve':'اعتماد الكتب والمعاملات','records.delete':'حذف الكتب والمعاملات',
    'requests.view':'مشاهدة الطلبات','requests.create':'إنشاء الطلبات','requests.review':'اعتماد أو رفض الطلبات',
    'tasks.view':'مشاهدة المهام','tasks.create':'إنشاء المهام','tasks.update':'تحديث المهام','tasks.delete':'حذف المهام',
    'meetings.view':'مشاهدة الاجتماعات','meetings.manage':'إدارة الاجتماعات والمحاضر',
    'attendance.view':'مشاهدة الحضور والانصراف','attendance.manage':'إدارة الحضور والانصراف',
    'inventory.view':'مشاهدة المخزن والعهد','inventory.manage':'إدارة المخزن والعهد',
    'news.manage':'إدارة الأخبار العامة',
    'files.view':'مشاهدة الملفات','files.upload':'رفع الملفات','files.download':'تنزيل الملفات','files.delete':'حذف الملفات',
    'users.manage':'إدارة المستخدمين والصلاحيات',
    'reports.view':'مشاهدة التقارير','audit.view':'مشاهدة سجل التدقيق',
}

DEPARTMENTS = ['الهيئة الإدارية','الإدارة','السكرتارية','الإعلام','المالية','النشاط الرياضي','الأرشيف','المخزن','الصيانة','المدربون']

def now_iso(): return datetime.now(timezone.utc).isoformat()
def db():
    con=sqlite3.connect(DB_PATH); con.row_factory=sqlite3.Row; con.execute('PRAGMA foreign_keys=ON'); return con

def ensure_column(con, table, column, definition):
    cols={r['name'] for r in con.execute(f'PRAGMA table_info({table})').fetchall()}
    if column not in cols: con.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')

def hash_password(password):
    salt=secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,PBKDF2_ITERATIONS)
    return f'{PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}'
def verify_password(password, encoded):
    try:
        it,salt,dig=encoded.split('$',2); got=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),int(it)); return hmac.compare_digest(got.hex(),dig)
    except Exception: return False

def create_token(user_id):
    payload={'sub':str(user_id),'iat':datetime.now(timezone.utc),'exp':datetime.now(timezone.utc)+timedelta(hours=TOKEN_HOURS)}
    return jwt.encode(payload,SECRET_KEY,algorithm=JWT_ALGORITHM)

def parse_permissions(raw):
    try: saved=json.loads(raw or '{}')
    except Exception: saved={}
    return {k:bool(saved.get(k,False)) for k in PERMISSIONS}

def public_user(row):
    return {'id':row['id'],'full_name':row['full_name'],'phone':row['phone'],'department':row['department'],'is_active':bool(row['is_active']),'permissions':parse_permissions(row['permissions']),'force_password_change':bool(row['force_password_change']) if 'force_password_change' in row.keys() else False,'created_at':row['created_at']}

def init_db():
    DATA_DIR.mkdir(parents=True,exist_ok=True)
    con=db()
    con.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,full_name TEXT NOT NULL UNIQUE,phone TEXT UNIQUE,password_hash TEXT NOT NULL,department TEXT NOT NULL DEFAULT 'الإدارة',is_active INTEGER NOT NULL DEFAULT 1,permissions TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS news(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,body TEXT NOT NULL,published INTEGER NOT NULL DEFAULT 1,created_by INTEGER,created_at TEXT NOT NULL,FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS notices(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,body TEXT NOT NULL,priority TEXT NOT NULL DEFAULT 'عادي',audience TEXT NOT NULL DEFAULT 'الجميع',created_by INTEGER,created_at TEXT NOT NULL,FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,owner TEXT NOT NULL,due_date TEXT,priority TEXT NOT NULL DEFAULT 'عادية',status TEXT NOT NULL DEFAULT 'مفتوحة',created_by INTEGER,created_at TEXT NOT NULL,FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY AUTOINCREMENT,type TEXT NOT NULL,number TEXT,department TEXT,record_date TEXT,subject TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'مسودة',created_by INTEGER,created_at TEXT NOT NULL,FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY AUTOINCREMENT,original_name TEXT NOT NULL,stored_name TEXT NOT NULL UNIQUE,mime_type TEXT,size INTEGER NOT NULL,uploaded_by INTEGER,created_at TEXT NOT NULL,FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,title TEXT NOT NULL,body TEXT NOT NULL,category TEXT NOT NULL DEFAULT 'عام',created_at TEXT NOT NULL,read_at TEXT,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT NOT NULL,entity TEXT NOT NULL,entity_id TEXT,details TEXT,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY AUTOINCREMENT,type TEXT NOT NULL,title TEXT NOT NULL,details TEXT,requester_id INTEGER,department TEXT,status TEXT NOT NULL DEFAULT 'قيد المراجعة',reviewed_by INTEGER,reviewed_at TEXT,review_note TEXT,created_at TEXT NOT NULL,FOREIGN KEY(requester_id) REFERENCES users(id) ON DELETE SET NULL,FOREIGN KEY(reviewed_by) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS meetings(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,meeting_date TEXT,location TEXT,agenda TEXT,minutes TEXT,status TEXT NOT NULL DEFAULT 'مجدول',created_by INTEGER,created_at TEXT NOT NULL,FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,work_date TEXT NOT NULL,check_in TEXT,check_out TEXT,status TEXT NOT NULL DEFAULT 'حاضر',note TEXT,created_by INTEGER,created_at TEXT NOT NULL,UNIQUE(user_id,work_date),FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS inventory(id INTEGER PRIMARY KEY AUTOINCREMENT,item_name TEXT NOT NULL,category TEXT,quantity REAL NOT NULL DEFAULT 0,unit TEXT NOT NULL DEFAULT 'قطعة',location TEXT,custodian TEXT,status TEXT NOT NULL DEFAULT 'متاح',notes TEXT,created_by INTEGER,created_at TEXT NOT NULL,FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS push_tokens(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,platform TEXT NOT NULL,token TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
    ''')
    ensure_column(con,'users','force_password_change','INTEGER NOT NULL DEFAULT 0')
    ensure_column(con,'users','last_login_at','TEXT')
    ensure_column(con,'files','entity_type','TEXT')
    ensure_column(con,'files','entity_id','INTEGER')
    name=os.getenv('ADMIN_NAME','مدير النظام'); phone=os.getenv('ADMIN_PHONE','07700000000'); password=os.getenv('ADMIN_PASSWORD','123456')
    admin=con.execute('SELECT id FROM users WHERE full_name=? OR phone=?',(name,phone)).fetchone()
    if not admin:
        allp={k:True for k in PERMISSIONS}
        cur=con.execute('INSERT INTO users(full_name,phone,password_hash,department,is_active,permissions,force_password_change,created_at) VALUES(?,?,?,?,?,?,?,?)',(name,phone,hash_password(password),'إدارة النظام',1,json.dumps(allp,ensure_ascii=False),1,now_iso())); aid=cur.lastrowid
        con.executemany('INSERT INTO news(title,body,published,created_by,created_at) VALUES(?,?,?,?,?)',[(t,b,1,aid,now_iso()) for t,b in [('الفريق الأول يواصل استعداداته','متابعة تحضيرات الفريق الأول لكرة القدم استعداداً للاستحقاقات المقبلة.'),('أكاديمية نادي آليات الشرطة تستقبل المواهب','تواصل الأكاديمية استقبال المواهب الرياضية ضمن برامجها التدريبية.'),('إنجازات جديدة لألعاب النادي','متابعة نتائج وإنجازات فرق النادي في البطولات المحلية.')]])
    con.commit(); con.close()

def audit(user_id,action,entity,entity_id=None,details=None):
    con=db(); con.execute('INSERT INTO audit_log(user_id,action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?,?)',(user_id,action,entity,str(entity_id) if entity_id is not None else None,json.dumps(details,ensure_ascii=False) if details is not None else None,now_iso())); con.commit(); con.close()

def notify_users(title,body,category='عام',audience='الجميع',specific_user_id=None):
    con=db()
    if specific_user_id:
        users=con.execute('SELECT id FROM users WHERE id=? AND is_active=1',(specific_user_id,)).fetchall()
    elif audience=='الجميع': users=con.execute('SELECT id FROM users WHERE is_active=1').fetchall()
    else: users=con.execute('SELECT id FROM users WHERE is_active=1 AND department=?',(audience,)).fetchall()
    con.executemany('INSERT INTO notifications(user_id,title,body,category,created_at) VALUES(?,?,?,?,?)',[(u['id'],title,body,category,now_iso()) for u in users]); con.commit(); con.close()

class LoginIn(BaseModel): identifier:str; password:str
class PasswordChange(BaseModel): current_password:str; new_password:str=Field(min_length=8,max_length=128)
class UserIn(BaseModel): full_name:str=Field(min_length=3,max_length=120); phone:str|None=None; password:str=Field(min_length=8,max_length=128); department:str='الإدارة'; permissions:dict[str,bool]={}; force_password_change:bool=True
class UserPatch(BaseModel): full_name:str|None=None; phone:str|None=None; password:str|None=None; department:str|None=None; is_active:bool|None=None; permissions:dict[str,bool]|None=None; force_password_change:bool|None=None
class NoticeIn(BaseModel): title:str; body:str; priority:str='عادي'; audience:str='الجميع'
class TaskIn(BaseModel): title:str; owner:str; due_date:str|None=None; priority:str='عادية'
class TaskPatch(BaseModel): title:str|None=None; owner:str|None=None; due_date:str|None=None; priority:str|None=None; status:str|None=None
class RecordIn(BaseModel): type:str; number:str|None=None; department:str|None=None; record_date:str|None=None; subject:str; status:str='مسودة'
class RecordPatch(BaseModel): type:str|None=None; number:str|None=None; department:str|None=None; record_date:str|None=None; subject:str|None=None; status:str|None=None
class NewsIn(BaseModel): title:str; body:str; published:bool=True
class RequestIn(BaseModel): type:str; title:str; details:str|None=None; department:str|None=None
class ReviewIn(BaseModel): decision:str; note:str|None=None
class MeetingIn(BaseModel): title:str; meeting_date:str|None=None; location:str|None=None; agenda:str|None=None; minutes:str|None=None; status:str='مجدول'
class AttendanceIn(BaseModel): user_id:int; work_date:str; check_in:str|None=None; check_out:str|None=None; status:str='حاضر'; note:str|None=None
class InventoryIn(BaseModel): item_name:str; category:str|None=None; quantity:float=0; unit:str='قطعة'; location:str|None=None; custodian:str|None=None; status:str='متاح'; notes:str|None=None
class PushTokenIn(BaseModel): platform:str; token:str

app=FastAPI(title='نادي آليات الشرطة الرياضي API',version='5.0')
origins=[x.strip() for x in os.getenv('CORS_ORIGINS','*').split(',') if x.strip()]
app.add_middleware(CORSMiddleware,allow_origins=origins,allow_methods=['*'],allow_headers=['*'])
@app.on_event('startup')
def startup(): init_db()

def current_user(authorization:str|None=Header(default=None)):
    if not authorization or not authorization.lower().startswith('bearer '): raise HTTPException(401,'يلزم تسجيل الدخول')
    try: payload=jwt.decode(authorization.split(' ',1)[1],SECRET_KEY,algorithms=[JWT_ALGORITHM]); uid=int(payload['sub'])
    except Exception: raise HTTPException(401,'جلسة غير صالحة أو منتهية')
    con=db(); row=con.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone(); con.close()
    if not row or not row['is_active']: raise HTTPException(401,'الحساب غير فعال')
    return public_user(row)
def require(permission):
    def dep(user=Depends(current_user)):
        if not user['permissions'].get(permission,False): raise HTTPException(403,'لا تملك الصلاحية المطلوبة')
        return user
    return dep

@app.get('/api/health')
def health(): return {'ok':True,'version':'5.0','time':now_iso()}
@app.get('/api/config/public')
def public_config(): return {'club_name':'نادي آليات الشرطة الرياضي','departments':DEPARTMENTS,'version':'5.0'}
@app.post('/api/auth/login')
def login(data:LoginIn):
    con=db(); row=con.execute('SELECT * FROM users WHERE (phone=? OR full_name=?) AND is_active=1',(data.identifier.strip(),data.identifier.strip())).fetchone()
    if not row or not verify_password(data.password,row['password_hash']): con.close(); raise HTTPException(401,'بيانات الدخول غير صحيحة')
    con.execute('UPDATE users SET last_login_at=? WHERE id=?',(now_iso(),row['id'])); con.commit(); con.close(); audit(row['id'],'login','auth')
    return {'token':create_token(row['id']),'user':public_user(row)}
@app.post('/api/auth/change-password')
def change_password(data:PasswordChange,user=Depends(current_user)):
    con=db(); row=con.execute('SELECT password_hash FROM users WHERE id=?',(user['id'],)).fetchone()
    if not row or not verify_password(data.current_password,row['password_hash']): con.close(); raise HTTPException(400,'كلمة المرور الحالية غير صحيحة')
    con.execute('UPDATE users SET password_hash=?, force_password_change=0 WHERE id=?',(hash_password(data.new_password),user['id'])); con.commit(); con.close(); audit(user['id'],'change_password','auth'); return {'ok':True}
@app.get('/api/me')
def me(user=Depends(current_user)): return {'user':user,'permission_labels':PERMISSIONS,'departments':DEPARTMENTS}

@app.get('/api/public/news')
def public_news():
    con=db(); rows=con.execute('SELECT id,title,body,created_at FROM news WHERE published=1 ORDER BY id DESC LIMIT 50').fetchall(); con.close(); return [dict(r) for r in rows]
@app.get('/api/news')
def list_news(user=Depends(current_user)):
    con=db(); rows=con.execute('SELECT * FROM news ORDER BY id DESC').fetchall(); con.close(); return [dict(r) for r in rows]
@app.post('/api/news')
def create_news(item:NewsIn,user=Depends(require('news.manage'))):
    con=db(); cur=con.execute('INSERT INTO news(title,body,published,created_by,created_at) VALUES(?,?,?,?,?)',(item.title,item.body,int(item.published),user['id'],now_iso())); con.commit(); nid=cur.lastrowid; con.close(); audit(user['id'],'create','news',nid); return {'id':nid}
@app.delete('/api/news/{news_id}')
def delete_news(news_id:int,user=Depends(require('news.manage'))):
    con=db(); con.execute('DELETE FROM news WHERE id=?',(news_id,)); con.commit(); con.close(); audit(user['id'],'delete','news',news_id); return {'ok':True}

@app.get('/api/notices')
def list_notices(user=Depends(require('notices.view'))):
    con=db(); rows=con.execute('SELECT * FROM notices ORDER BY id DESC LIMIT 200').fetchall(); con.close(); return [dict(r) for r in rows]
@app.post('/api/notices')
def create_notice(item:NoticeIn,user=Depends(require('notices.create'))):
    con=db(); cur=con.execute('INSERT INTO notices(title,body,priority,audience,created_by,created_at) VALUES(?,?,?,?,?,?)',(item.title,item.body,item.priority,item.audience,user['id'],now_iso())); nid=cur.lastrowid; con.commit(); con.close(); notify_users(item.title,item.body,'تبليغ',item.audience); audit(user['id'],'create','notice',nid); return {'id':nid}
@app.delete('/api/notices/{notice_id}')
def delete_notice(notice_id:int,user=Depends(require('notices.delete'))):
    con=db(); con.execute('DELETE FROM notices WHERE id=?',(notice_id,)); con.commit(); con.close(); audit(user['id'],'delete','notice',notice_id); return {'ok':True}

@app.get('/api/tasks')
def list_tasks(user=Depends(require('tasks.view'))):
    con=db(); rows=con.execute('SELECT * FROM tasks ORDER BY id DESC').fetchall(); con.close(); return [dict(r) for r in rows]
@app.post('/api/tasks')
def create_task(item:TaskIn,user=Depends(require('tasks.create'))):
    con=db(); cur=con.execute('INSERT INTO tasks(title,owner,due_date,priority,status,created_by,created_at) VALUES(?,?,?,?,?,?,?)',(item.title,item.owner,item.due_date,item.priority,'مفتوحة',user['id'],now_iso())); tid=cur.lastrowid; con.commit(); con.close(); audit(user['id'],'create','task',tid); return {'id':tid}
@app.patch('/api/tasks/{task_id}')
def patch_task(task_id:int,item:TaskPatch,user=Depends(require('tasks.update'))):
    payload=item.model_dump(exclude_none=True)
    if payload:
        con=db(); con.execute('UPDATE tasks SET '+', '.join(f'{k}=?' for k in payload)+' WHERE id=?',(*payload.values(),task_id)); con.commit(); con.close(); audit(user['id'],'update','task',task_id,payload)
    return {'ok':True}
@app.delete('/api/tasks/{task_id}')
def delete_task(task_id:int,user=Depends(require('tasks.delete'))):
    con=db(); con.execute('DELETE FROM tasks WHERE id=?',(task_id,)); con.commit(); con.close(); audit(user['id'],'delete','task',task_id); return {'ok':True}

@app.get('/api/records')
def list_records(user=Depends(require('records.view'))):
    con=db(); rows=con.execute('SELECT * FROM records ORDER BY id DESC').fetchall(); con.close(); return [dict(r) for r in rows]
@app.post('/api/records')
def create_record(item:RecordIn,user=Depends(require('records.create'))):
    con=db(); cur=con.execute('INSERT INTO records(type,number,department,record_date,subject,status,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)',(item.type,item.number,item.department,item.record_date,item.subject,item.status,user['id'],now_iso())); rid=cur.lastrowid; con.commit(); con.close(); audit(user['id'],'create','record',rid); return {'id':rid}
@app.patch('/api/records/{record_id}')
def patch_record(record_id:int,item:RecordPatch,user=Depends(require('records.update'))):
    payload=item.model_dump(exclude_none=True)
    if payload:
        con=db(); con.execute('UPDATE records SET '+', '.join(f'{k}=?' for k in payload)+' WHERE id=?',(*payload.values(),record_id)); con.commit(); con.close(); audit(user['id'],'update','record',record_id,payload)
    return {'ok':True}
@app.post('/api/records/{record_id}/approve')
def approve_record(record_id:int,user=Depends(require('records.approve'))):
    con=db(); con.execute("UPDATE records SET status='معتمد' WHERE id=?",(record_id,)); con.commit(); con.close(); audit(user['id'],'approve','record',record_id); return {'ok':True}
@app.delete('/api/records/{record_id}')
def delete_record(record_id:int,user=Depends(require('records.delete'))):
    con=db(); con.execute('DELETE FROM records WHERE id=?',(record_id,)); con.commit(); con.close(); audit(user['id'],'delete','record',record_id); return {'ok':True}

@app.get('/api/requests')
def list_requests(user=Depends(require('requests.view'))):
    con=db(); rows=con.execute('SELECT r.*,u.full_name requester_name,rv.full_name reviewer_name FROM requests r LEFT JOIN users u ON u.id=r.requester_id LEFT JOIN users rv ON rv.id=r.reviewed_by ORDER BY r.id DESC').fetchall(); con.close(); return [dict(r) for r in rows]
@app.post('/api/requests')
def create_request(item:RequestIn,user=Depends(require('requests.create'))):
    con=db(); cur=con.execute('INSERT INTO requests(type,title,details,requester_id,department,status,created_at) VALUES(?,?,?,?,?,?,?)',(item.type,item.title,item.details,user['id'],item.department or user['department'],'قيد المراجعة',now_iso())); rid=cur.lastrowid; con.commit(); con.close(); notify_users('طلب إداري جديد',item.title,'طلب','الإدارة'); audit(user['id'],'create','request',rid); return {'id':rid}
@app.post('/api/requests/{request_id}/review')
def review_request(request_id:int,item:ReviewIn,user=Depends(require('requests.review'))):
    if item.decision not in ['مقبول','مرفوض','بحاجة تعديل']: raise HTTPException(400,'قرار غير صحيح')
    con=db(); row=con.execute('SELECT requester_id,title FROM requests WHERE id=?',(request_id,)).fetchone()
    if not row: con.close(); raise HTTPException(404,'الطلب غير موجود')
    con.execute('UPDATE requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? WHERE id=?',(item.decision,user['id'],now_iso(),item.note,request_id)); con.commit(); con.close(); notify_users('تحديث حالة الطلب',f"{row['title']}: {item.decision}",'طلب',specific_user_id=row['requester_id']); audit(user['id'],'review','request',request_id,{'decision':item.decision,'note':item.note}); return {'ok':True}

@app.get('/api/meetings')
def list_meetings(user=Depends(require('meetings.view'))):
    con=db(); rows=con.execute('SELECT * FROM meetings ORDER BY COALESCE(meeting_date,created_at) DESC').fetchall(); con.close(); return [dict(r) for r in rows]
@app.post('/api/meetings')
def create_meeting(item:MeetingIn,user=Depends(require('meetings.manage'))):
    con=db(); cur=con.execute('INSERT INTO meetings(title,meeting_date,location,agenda,minutes,status,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)',(item.title,item.meeting_date,item.location,item.agenda,item.minutes,item.status,user['id'],now_iso())); mid=cur.lastrowid; con.commit(); con.close(); notify_users('اجتماع جديد',item.title,'اجتماع','الجميع'); audit(user['id'],'create','meeting',mid); return {'id':mid}
@app.patch('/api/meetings/{meeting_id}')
def patch_meeting(meeting_id:int,item:MeetingIn,user=Depends(require('meetings.manage'))):
    payload=item.model_dump(); con=db(); con.execute('UPDATE meetings SET title=?,meeting_date=?,location=?,agenda=?,minutes=?,status=? WHERE id=?',(payload['title'],payload['meeting_date'],payload['location'],payload['agenda'],payload['minutes'],payload['status'],meeting_id)); con.commit(); con.close(); audit(user['id'],'update','meeting',meeting_id); return {'ok':True}

@app.get('/api/attendance')
def list_attendance(user=Depends(require('attendance.view'))):
    con=db(); rows=con.execute('SELECT a.*,u.full_name,u.department FROM attendance a JOIN users u ON u.id=a.user_id ORDER BY work_date DESC,a.id DESC LIMIT 500').fetchall(); con.close(); return [dict(r) for r in rows]
@app.get('/api/attendance/me')
def my_attendance(user=Depends(current_user)):
    con=db(); rows=con.execute('SELECT * FROM attendance WHERE user_id=? ORDER BY work_date DESC LIMIT 60',(user['id'],)).fetchall(); con.close(); return [dict(r) for r in rows]
@app.post('/api/attendance')
def upsert_attendance(item:AttendanceIn,user=Depends(require('attendance.manage'))):
    con=db(); con.execute('INSERT INTO attendance(user_id,work_date,check_in,check_out,status,note,created_by,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_id,work_date) DO UPDATE SET check_in=excluded.check_in,check_out=excluded.check_out,status=excluded.status,note=excluded.note,created_by=excluded.created_by',(item.user_id,item.work_date,item.check_in,item.check_out,item.status,item.note,user['id'],now_iso())); con.commit(); con.close(); audit(user['id'],'upsert','attendance',f'{item.user_id}:{item.work_date}'); return {'ok':True}

@app.get('/api/inventory')
def list_inventory(user=Depends(require('inventory.view'))):
    con=db(); rows=con.execute('SELECT * FROM inventory ORDER BY id DESC').fetchall(); con.close(); return [dict(r) for r in rows]
@app.post('/api/inventory')
def create_inventory(item:InventoryIn,user=Depends(require('inventory.manage'))):
    con=db(); cur=con.execute('INSERT INTO inventory(item_name,category,quantity,unit,location,custodian,status,notes,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(item.item_name,item.category,item.quantity,item.unit,item.location,item.custodian,item.status,item.notes,user['id'],now_iso())); iid=cur.lastrowid; con.commit(); con.close(); audit(user['id'],'create','inventory',iid); return {'id':iid}
@app.patch('/api/inventory/{item_id}')
def patch_inventory(item_id:int,item:InventoryIn,user=Depends(require('inventory.manage'))):
    con=db(); con.execute('UPDATE inventory SET item_name=?,category=?,quantity=?,unit=?,location=?,custodian=?,status=?,notes=? WHERE id=?',(item.item_name,item.category,item.quantity,item.unit,item.location,item.custodian,item.status,item.notes,item_id)); con.commit(); con.close(); audit(user['id'],'update','inventory',item_id); return {'ok':True}

@app.get('/api/users')
def list_users(user=Depends(require('users.manage'))):
    con=db(); rows=con.execute('SELECT * FROM users ORDER BY id DESC').fetchall(); con.close(); return [public_user(r) for r in rows]
@app.get('/api/users/basic')
def basic_users(user=Depends(current_user)):
    con=db(); rows=con.execute('SELECT id,full_name,department FROM users WHERE is_active=1 ORDER BY full_name').fetchall(); con.close(); return [dict(r) for r in rows]
@app.get('/api/permissions')
def permissions(user=Depends(require('users.manage'))): return PERMISSIONS
@app.post('/api/users')
def create_user(item:UserIn,user=Depends(require('users.manage'))):
    cleaned={k:bool(item.permissions.get(k,False)) for k in PERMISSIONS}
    try:
        con=db(); cur=con.execute('INSERT INTO users(full_name,phone,password_hash,department,is_active,permissions,force_password_change,created_at) VALUES(?,?,?,?,?,?,?,?)',(item.full_name.strip(),item.phone.strip() if item.phone else None,hash_password(item.password),item.department,1,json.dumps(cleaned,ensure_ascii=False),int(item.force_password_change),now_iso())); uid=cur.lastrowid; con.commit(); con.close()
    except sqlite3.IntegrityError: raise HTTPException(409,'الاسم أو رقم الهاتف مستخدم مسبقاً')
    audit(user['id'],'create','user',uid,{'full_name':item.full_name,'department':item.department}); return {'id':uid}
@app.patch('/api/users/{user_id}')
def patch_user(user_id:int,item:UserPatch,user=Depends(require('users.manage'))):
    if user_id==user['id'] and item.is_active is False: raise HTTPException(400,'لا يمكن تعطيل الحساب الحالي')
    payload=item.model_dump(exclude_none=True)
    if 'permissions' in payload: payload['permissions']=json.dumps({k:bool(payload['permissions'].get(k,False)) for k in PERMISSIONS},ensure_ascii=False)
    if 'password' in payload: payload['password_hash']=hash_password(payload.pop('password'))
    if not payload: return {'ok':True}
    try:
        con=db(); con.execute('UPDATE users SET '+', '.join(f'{k}=?' for k in payload)+' WHERE id=?',(*payload.values(),user_id)); con.commit(); con.close()
    except sqlite3.IntegrityError: raise HTTPException(409,'الاسم أو رقم الهاتف مستخدم مسبقاً')
    audit(user['id'],'update','user',user_id,{k:('***' if 'password' in k else v) for k,v in payload.items()}); return {'ok':True}

@app.get('/api/files')
def list_files(user=Depends(require('files.view'))):
    con=db(); rows=con.execute('SELECT f.*,u.full_name uploader_name FROM files f LEFT JOIN users u ON u.id=f.uploaded_by ORDER BY f.id DESC').fetchall(); con.close(); return [dict(r) for r in rows]
@app.post('/api/files')
async def upload_file(file:UploadFile=File(...),entity_type:str|None=None,entity_id:int|None=None,user=Depends(require('files.upload'))):
    suffix=Path(file.filename or 'file.bin').suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS: raise HTTPException(415,'نوع الملف غير مسموح')
    stored=f'{uuid.uuid4().hex}{suffix}'; target=UPLOAD_DIR/stored; size=0
    with target.open('wb') as out:
        while True:
            chunk=await file.read(1024*1024)
            if not chunk: break
            size+=len(chunk)
            if size>MAX_FILE_SIZE: out.close(); target.unlink(missing_ok=True); raise HTTPException(413,'حجم الملف يتجاوز الحد المسموح')
            out.write(chunk)
    mime=file.content_type or mimetypes.guess_type(file.filename or '')[0] or 'application/octet-stream'
    con=db(); cur=con.execute('INSERT INTO files(original_name,stored_name,mime_type,size,uploaded_by,created_at,entity_type,entity_id) VALUES(?,?,?,?,?,?,?,?)',(file.filename or stored,stored,mime,size,user['id'],now_iso(),entity_type,entity_id)); fid=cur.lastrowid; con.commit(); con.close(); audit(user['id'],'upload','file',fid,{'name':file.filename,'size':size}); return {'id':fid,'size':size}
@app.get('/api/files/{file_id}/download')
def download_file(file_id:int,user=Depends(require('files.download'))):
    con=db(); row=con.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone(); con.close()
    if not row: raise HTTPException(404,'الملف غير موجود')
    path=UPLOAD_DIR/row['stored_name']
    if not path.exists(): raise HTTPException(404,'الملف مفقود من الخادم')
    audit(user['id'],'download','file',file_id); return FileResponse(path,media_type=row['mime_type'],filename=row['original_name'])
@app.delete('/api/files/{file_id}')
def delete_file(file_id:int,user=Depends(require('files.delete'))):
    con=db(); row=con.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone()
    if not row: con.close(); raise HTTPException(404,'الملف غير موجود')
    con.execute('DELETE FROM files WHERE id=?',(file_id,)); con.commit(); con.close(); (UPLOAD_DIR/row['stored_name']).unlink(missing_ok=True); audit(user['id'],'delete','file',file_id); return {'ok':True}

@app.get('/api/notifications')
def notifications(user=Depends(current_user)):
    con=db(); rows=con.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100',(user['id'],)).fetchall(); con.close(); return [dict(r) for r in rows]
@app.get('/api/notifications/unread-count')
def unread_count(user=Depends(current_user)):
    con=db(); c=con.execute('SELECT COUNT(*) c FROM notifications WHERE user_id=? AND read_at IS NULL',(user['id'],)).fetchone()['c']; con.close(); return {'count':c}
@app.post('/api/notifications/{notification_id}/read')
def mark_read(notification_id:int,user=Depends(current_user)):
    con=db(); con.execute('UPDATE notifications SET read_at=? WHERE id=? AND user_id=?',(now_iso(),notification_id,user['id'])); con.commit(); con.close(); return {'ok':True}
@app.post('/api/notifications/read-all')
def mark_all_read(user=Depends(current_user)):
    con=db(); con.execute('UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL',(now_iso(),user['id'])); con.commit(); con.close(); return {'ok':True}
@app.post('/api/push/register')
def register_push(item:PushTokenIn,user=Depends(current_user)):
    con=db(); con.execute('INSERT INTO push_tokens(user_id,platform,token,created_at) VALUES(?,?,?,?) ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id,platform=excluded.platform',(user['id'],item.platform,item.token,now_iso())); con.commit(); con.close(); return {'ok':True}

@app.get('/api/stats')
def stats(user=Depends(require('dashboard.view'))):
    con=db(); result={'notices':con.execute('SELECT COUNT(*) c FROM notices').fetchone()['c'],'open_tasks':con.execute("SELECT COUNT(*) c FROM tasks WHERE status!='منجزة'").fetchone()['c'],'records':con.execute('SELECT COUNT(*) c FROM records').fetchone()['c'],'users':con.execute('SELECT COUNT(*) c FROM users WHERE is_active=1').fetchone()['c'],'pending_requests':con.execute("SELECT COUNT(*) c FROM requests WHERE status='قيد المراجعة'").fetchone()['c'],'inventory_items':con.execute('SELECT COUNT(*) c FROM inventory').fetchone()['c']}; con.close(); return result
@app.get('/api/reports/summary')
def report_summary(user=Depends(require('reports.view'))):
    con=db(); result={'records_by_status':[dict(r) for r in con.execute('SELECT status,COUNT(*) count FROM records GROUP BY status').fetchall()],'requests_by_status':[dict(r) for r in con.execute('SELECT status,COUNT(*) count FROM requests GROUP BY status').fetchall()],'attendance_by_status':[dict(r) for r in con.execute('SELECT status,COUNT(*) count FROM attendance GROUP BY status').fetchall()],'inventory_total':con.execute('SELECT COALESCE(SUM(quantity),0) total FROM inventory').fetchone()['total']}; con.close(); return result

def csv_response(rows,headers,filename):
    s=io.StringIO(); w=csv.writer(s); w.writerow(headers)
    for r in rows: w.writerow([r.get(h,'') for h in headers])
    data='\ufeff'+s.getvalue(); return StreamingResponse(iter([data.encode('utf-8')]),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':f'attachment; filename="{filename}"'})
@app.get('/api/reports/records.csv')
def records_csv(user=Depends(require('reports.view'))):
    con=db(); rows=[dict(r) for r in con.execute('SELECT id,type,number,department,record_date,subject,status,created_at FROM records ORDER BY id DESC').fetchall()]; con.close(); return csv_response(rows,['id','type','number','department','record_date','subject','status','created_at'],'records.csv')
@app.get('/api/reports/attendance.csv')
def attendance_csv(user=Depends(require('reports.view'))):
    con=db(); rows=[dict(r) for r in con.execute('SELECT a.id,u.full_name,a.work_date,a.check_in,a.check_out,a.status,a.note FROM attendance a JOIN users u ON u.id=a.user_id ORDER BY a.work_date DESC').fetchall()]; con.close(); return csv_response(rows,['id','full_name','work_date','check_in','check_out','status','note'],'attendance.csv')
@app.get('/api/audit')
def audit_list(user=Depends(require('audit.view'))):
    con=db(); rows=con.execute('SELECT a.*,u.full_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 500').fetchall(); con.close(); return [dict(r) for r in rows]

app.mount('/',StaticFiles(directory=FRONTEND_DIR,html=True),name='frontend')
