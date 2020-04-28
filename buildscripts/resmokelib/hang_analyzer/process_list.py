"""Functions to list processes in each OS and search for interesting processes."""

import io
import csv
import os
import sys
import logging
import subprocess
from distutils import spawn  # pylint: disable=no-name-in-module

from buildscripts.resmokelib import core


def get_processes(process_ids, interesting_processes, process_match, logger):
    """
    Find all running interesting processes.

    If a list of process_ids is supplied, match on that.
    Otherwise, do a substring match on interesting_processes.

    :param process_ids: List of PIDs to match on.
    :param interesting_processes: List of process names to match on.
    :param process_match: Member of ProcessMatch enum type describe the match to use.
    :param logger: Where to log output.

    :return: A list of (pid, pname) pairs.
    """
    ps = get_lister()

    all_processes = ps.dump_processes(logger)

    # Canonicalize the process names to lowercase to handle cases where the name of the Python
    # process is /System/Library/.../Python on OS X and -p python is specified to hang_analyzer.py.
    all_processes = [(pid, process_name.lower()) for (pid, process_name) in all_processes]

    if process_ids:
        processes = [(pid, pname) for (pid, pname) in all_processes
                     if pid in process_ids and pid != os.getpid()]

        running_pids = {pid for (pid, pname) in all_processes}
        missing_pids = set(process_ids) - running_pids
        if missing_pids:
            logger.warning("The following requested process ids are not running %s",
                           list(missing_pids))
    else:
        processes = [
            (pid, pname) for (pid, pname) in all_processes
            if _pname_match(process_match, pname, interesting_processes) and pid != os.getpid()
        ]

    logger.info("Found %d interesting processes %s", len(processes), processes)
    return processes


def get_lister():
    """Return ProcessList object for OS."""
    if sys.platform.startswith("linux"):
        ps = LinuxProcessList()
    elif sys.platform.startswith("sunos"):
        ps = SolarisProcessList()
    elif sys.platform == "win32" or sys.platform == "cygwin":
        ps = WindowsProcessList()
    elif sys.platform == "darwin":
        ps = DarwinProcessList()
    else:
        raise OSError("Hang analyzer: Unsupported platform: {}".format(sys.platform))

    return ps


class ProcessList(object):
    """Abstract base class for all process listers."""

    def dump_processes(self, logger):
        """
        Find all processes.

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


# TODO: Defined twice
def call(args, logger):
    """Call subprocess on args list."""
    logger.info(str(args))

    # Use a common pipe for stdout & stderr for logging.
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logger_pipe = core.pipe.LoggerPipe(logger, logging.INFO, process.stdout)
    logger_pipe.wait_until_started()

    ret = process.wait()
    logger_pipe.wait_until_finished()

    if ret != 0:
        logger.error("Bad exit code %d", ret)
        raise Exception("Bad exit code %d from %s" % (ret, " ".join(args)))


def _pname_match(match_type, pname, interesting_processes):
    """Return True if the pname matches an interesting_processes."""
    pname = os.path.splitext(pname)[0]
    for ip in interesting_processes:
        if match_type == 'exact' and pname == ip or match_type == 'contains' and ip in pname:
            return True
    return False
