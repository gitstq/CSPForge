"""支持 ``python -m cspforge`` 运行。"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
