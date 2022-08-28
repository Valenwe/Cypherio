import cx_Freeze, sys

base = None
if sys.platform == 'win32':
    base = 'Win32GUI'

executables = [cx_Freeze.Executable("cypherio.py", base=base), cx_Freeze.Executable("crypto.py", base=base)]

cx_Freeze.setup(
    name="Cypherio",
    options={"build_exe": {"packages":["Cryptodome", "os", "sys", "subprocess", "PySimpleGUI"], "include_files": ["favicon.ico"]}},
    executables = executables)