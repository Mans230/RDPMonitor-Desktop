# PyInstaller onedir bundle; the interpreter and every import live under Program Files.
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules

root = Path(SPECPATH).parent
hidden = ['agent.__main__', 'agent.service', 'agent.migration', 'agent.management',
          'servicemanager', 'win32timezone', 'win32serviceutil', 'win32security',
          'win32crypt', 'win32pipe', 'win32file', 'win32ts', 'win32profile',
          'win32process', 'win32event', 'win32con', 'win32api', 'win32service',
          'win32net', 'win32netcon', 'pywintypes', 'pythoncom', 'PIL.ImageGrab']
hidden += collect_submodules('uvicorn') + collect_submodules('matplotlib.backends.backend_agg')
datas = [(str(root / 'rdp_monitor.py'), '.'),
         (str(root / 'backup' / 'app'), 'backup/app'),
         (str(root / 'config.example.json'), '.'),
         (str(root / 'backup' / 'config.example.json'), 'backup'),
         (str(root / 'scripts'), 'scripts'),
         (str(root / 'LICENSE'), '.')]
binaries = []
for package in ('cryptography', 'pyzipper', 'psutil', 'tzdata'):
    extra_data, extra_binaries, extra_hidden = collect_all(package)
    datas += extra_data; binaries += extra_binaries; hidden += extra_hidden
analysis = Analysis([str(root / 'scripts' / 'agent_entry.py')], pathex=[str(root), str(root / 'backup' / 'app')],
                    binaries=binaries, datas=datas, hiddenimports=hidden,
                    excludes=['pytest', 'tests'], noarchive=False)
pyz = PYZ(analysis.pure)
exe = EXE(pyz, analysis.scripts, [], exclude_binaries=True, name='RDPMonitorAgent',
          debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
          console=True, contents_directory='runtime')
app = COLLECT(exe, analysis.binaries, analysis.datas, strip=False, upx=False, name='RDPMonitorAgent')
