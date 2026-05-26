# -*- mode: python ; coding: utf-8 -*-
# Build: pyinstaller memguard.spec

from pathlib import Path

block_cipher = None

a = Analysis(
    ['run.py'],
    pathex=[str(Path('.').resolve())],
    binaries=[],
    datas=[
        ('MemGuard/static',   'MemGuard/static'),
        ('MemGuard/.env',     'MemGuard'),
    ],
    hiddenimports=[
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'fastapi',
        'pydantic',
        'pydantic_settings',
        'chromadb',
        'apscheduler',
        'structlog',
        'cryptography',
        'openai',
        'anthropic',
        'litellm',
        'aiofiles',
        'anyio',
        'anyio._backends._asyncio',
        'starlette.staticfiles',
        'starlette.responses',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='MemGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='MemGuard',
)
