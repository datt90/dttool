import logging
import sys
from typing import Any, Optional

from hgf import __version__
from hgf.exceptions import OperationalException

# check min. python version (>= 3.10 required)
if sys.version_info < (3, 10):  # pragma: no cover
  sys.exit("Hgf requires Python version >= 3.10")

from hgf.commands import Arguments

logger = logging.getLogger("hgf")
def main(sysargv: Optional[list[str]] = None) -> None:
  return_code: Any = 1
  try:
    print("Hgf CLI")
    arguments = Arguments(sysargv)
    args = arguments.get_parsed_arg()

    # Call subcommand.
    if "func" in args:
        logger.info(f"hgf {__version__}")
        return_code = args["func"](args)
    else:
        # No subcommand was issued.
        raise OperationalException(
            "Usage of Hgf requires a subcommand to be specified.\n"
            "To see the full list of options available, please use "
            "`hgf --help` or `hgf <command> --help`."
        )
  finally:
    print("Exiting hgf")
    sys.exit(return_code)
  
if __name__ == "__main__":  # pragma: no cover
  main()