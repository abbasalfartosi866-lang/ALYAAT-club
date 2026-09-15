from pathlib import Path
import shutil, datetime
base=Path(__file__).resolve().parent
src=base/'data'
dst=base/'backups'/datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
dst.parent.mkdir(exist_ok=True)
shutil.copytree(src,dst)
print(dst)
