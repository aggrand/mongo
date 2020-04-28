import io
import csv
import os
import sys
import subprocess
#TODO: defined twice
_IS_WINDOWS = (sys.platform == "win32")

def get_lister():
    """Return process lister for OS."""
    if sys.platform.startswith("linux"):
        ps = LinuxProcessList()
    elif sys.platform.startswith("sunos"):
        ps = SolarisProcessList()
    elif _IS_WINDOWS or sys.platform == "cygwin":
        ps = WindowsProcessList()
    elif sys.platform == "darwin":
        ps = DarwinProcessList()

    return ps

class ProcessList(object):
    """Abstract base class for all process listers."""

    def dump_processes(self, logger):
        """
        Finds all processes.

        :param logger: Where to log output.
        :return: A list of process names.
        """
        raise NotImplementedError("dump_process must be implemented in OS-specific subclasses")


class WindowsProcessList(ProcessList):
    """WindowsProcessList class."""

    @staticmethod
    def __find_ps():
        """Find tasklist."""
        return os.path.join(os.environ["WINDIR"], "system32", "tasklist.exe")

    def dump_processes(self, logger):
        """Get list of [Pid, Process Name]."""
        ps = self.__find_ps()

        logger.info("Getting list of processes using %s", ps)

        ret = callo([ps, "/FO", "CSV"], logger)

        buff = io.StringIO(ret)
        csv_reader = csv.reader(buff)

        return [[int(row[1]), row[0]] for row in csv_reader if row[1] != "PID"]

class DarwinProcessList(ProcessList):
    """DarwinProcessList class."""

    @staticmethod
    def __find_ps():
        """Find ps."""
        return find_program('ps', ['/bin'])

    def dump_processes(self, logger):
        """Get list of [Pid, Process Name]."""
        ps = self.__find_ps()

        logger.info("Getting list of processes using %s", ps)

        ret = callo([ps, "-axco", "pid,comm"], logger)

        buff = io.StringIO(ret)
        csv_reader = csv.reader(buff, delimiter=' ', quoting=csv.QUOTE_NONE, skipinitialspace=True)

        return [[int(row[0]), row[1]] for row in csv_reader if row[0] != "PID"]

class LinuxProcessList(ProcessList):
    """LinuxProcessList class."""

    @staticmethod
    def __find_ps():
        """Find ps."""
        return find_program('ps', ['/bin', '/usr/bin'])

    def dump_processes(self, logger):
        """Get list of [Pid, Process Name]."""
        ps = self.__find_ps()

        logger.info("Getting list of processes using %s", ps)

        call([ps, "--version"], logger)

        ret = callo([ps, "-eo", "pid,args"], logger)

        buff = io.StringIO(ret)
        csv_reader = csv.reader(buff, delimiter=' ', quoting=csv.QUOTE_NONE, skipinitialspace=True)

        return [[int(row[0]), os.path.split(row[1])[1]] for row in csv_reader if row[0] != "PID"]

class SolarisProcessList(ProcessList):
    """SolarisProcessList class."""

    @staticmethod
    def __find_ps():
        """Find ps."""
        return find_program('ps', ['/bin', '/usr/bin'])

    def dump_processes(self, logger):
        """Get list of [Pid, Process Name]."""
        ps = self.__find_ps()

        logger.info("Getting list of processes using %s", ps)

        ret = callo([ps, "-eo", "pid,args"], logger)

        buff = io.StringIO(ret)
        csv_reader = csv.reader(buff, delimiter=' ', quoting=csv.QUOTE_NONE, skipinitialspace=True)

        return [[int(row[0]), os.path.split(row[1])[1]] for row in csv_reader if row[0] != "PID"]

# TODO: Defined twice
def callo(args, logger):
    """Call subprocess on args string."""
    logger.info("%s", str(args))

    return subprocess.check_output(args).decode('utf-8', 'replace')

# TODO: Defined twice
def find_program(prog, paths):
    """Find the specified program in env PATH, or tries a set of paths."""
    for loc in paths:
        full_prog = os.path.join(loc, prog)
        if os.path.exists(full_prog):
            return full_prog

    return spawn.find_executable(prog)

