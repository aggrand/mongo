"""Hang Analyzer module.

A prototype hang analyzer for Evergreen integration to help investigate test timeouts

1. Script supports taking dumps, and/or dumping a summary of useful information about a process
2. Script will iterate through a list of interesting processes,
    and run the tools from step 1. The list of processes can be provided as an option.
3. Java processes will be dumped using jstack, if available.

Supports Linux, MacOS X, Solaris, and Windows.
"""
import io
import csv
import glob
import logging
import os
import platform
import re
import signal
import subprocess
import sys
import traceback
import time
from distutils import spawn  # pylint: disable=no-name-in-module
from optparse import OptionParser
from buildscripts.resmokelib.commands import interface
from buildscripts.resmokelib.hang_analyzer import process_list
from buildscripts.resmokelib.hang_analyzer import dumper

_IS_WINDOWS = (sys.platform == "win32")

if _IS_WINDOWS:
    import win32event
    import win32api

def get_process_logger(debugger_output, pinfo):
    """Return the process logger from options specified."""
    process_logger = logging.Logger("process", level=logging.DEBUG)
    process_logger.mongo_process_filename = None

    if 'stdout' in debugger_output:
        s_handler = logging.StreamHandler(sys.stdout)
        s_handler.setFormatter(logging.Formatter(fmt="%(message)s"))
        process_logger.addHandler(s_handler)

    if 'file' in debugger_output:
        filename = "debugger_%s_%d.log" % (os.path.splitext(pinfo.name)[0], pinfo.pid)
        process_logger.mongo_process_filename = filename
        f_handler = logging.FileHandler(filename=filename, mode="w")
        f_handler.setFormatter(logging.Formatter(fmt="%(message)s"))
        process_logger.addHandler(f_handler)

    return process_logger

class DebugExtractor(object):
    """Extracts `mongo-debugsymbols.tgz`."""

    @staticmethod
    def extract_debug_symbols(root_logger):
        """
        Extract debug symbols. Idempotent.

        :param root_logger: logger to use
        :return: None
        """
        path = os.path.join(os.getcwd(), 'mongo-debugsymbols.tgz')
        root_logger.debug('Starting: Extract debug-symbols from %s.', path)
        if not os.path.exists(path):
            root_logger.info('Debug-symbols archive-file does not exist. '
                             'Hang-Analyzer may not complete successfully, '
                             'or debug-symbols may already be extracted.')
            return
        try:
            DebugExtractor._exxtract_tar(path, root_logger)
            root_logger.debug('Finished: Extract debug-symbols from %s.', path)
        # We never want this to cause the whole task to fail.
        # The rest of hang_analyzer.py will continue to work without the
        # symbols it just won't be quite as helpful.
        # pylint: disable=broad-except
        except Exception as exception:
            root_logger.warning('Error when extracting %s: %s', path, exception)

    @staticmethod
    def _exxtract_tar(path, root_logger):
        import shutil
        # The file name is always .tgz but it's "secretly" a zip file on Windows :(
        compressed_format = 'zip' if _IS_WINDOWS else 'gztar'
        shutil.unpack_archive(path, format=compressed_format)
        for (src, dest) in DebugExtractor._extracted_files_to_copy():
            if os.path.exists(dest):
                root_logger.debug('Debug symbol %s already exists, not copying from %s.', dest, src)
                continue
            shutil.copy(src, dest)
            root_logger.debug('Copied debug symbol %s.', dest)

    @staticmethod
    def _extracted_files_to_copy():
        out = []
        for ext in ['debug', 'dSYM', 'pdb']:
            for file in ['mongo', 'mongod', 'mongos']:
                haystack = os.path.join('dist-test', 'bin', '{file}.{ext}'.format(
                    file=file, ext=ext))
                for needle in glob.glob(haystack):
                    out.append((needle, os.path.join(os.getcwd(), os.path.basename(needle))))
        return out

def check_dump_quota(quota, ext):
    """Check if sum of the files with ext is within the specified quota in megabytes."""

    files = glob.glob("*." + ext)

    size_sum = 0
    for file_name in files:
        size_sum += os.path.getsize(file_name)

    return size_sum <= quota

def signal_event_object(logger, pid):
    """Signal the Windows event object."""

    # Use unique event_name created.
    event_name = "Global\\Mongo_Python_" + str(pid)

    try:
        desired_access = win32event.EVENT_MODIFY_STATE
        inherit_handle = False
        task_timeout_handle = win32event.OpenEvent(desired_access, inherit_handle, event_name)
    except win32event.error as err:
        logger.info("Exception from win32event.OpenEvent with error: %s", err)
        return

    try:
        win32event.SetEvent(task_timeout_handle)
    except win32event.error as err:
        logger.info("Exception from win32event.SetEvent with error: %s", err)
    finally:
        win32api.CloseHandle(task_timeout_handle)

    logger.info("Waiting for process to report")
    time.sleep(5)


def signal_process(logger, pid, signalnum):
    """Signal process with signal, N/A on Windows."""
    try:
        os.kill(pid, signalnum)

        logger.info("Waiting for process to report")
        time.sleep(5)
    except OSError as err:
        logger.error("Hit OS error trying to signal process: %s", err)

    except AttributeError:
        logger.error("Cannot send signal to a process on Windows")


class HangAnalyzer(interface.Subcommand):
    """Main class for the hang analyzer subcommand."""

    def __init__(self, options):
        """
        Configure processe lists based on options.

        :param options: Options as parsed by parser.py
        """
        self.options = options
        self.root_logger = None
        self.interesting_processes = [
            "mongo", "mongod", "mongos", "_test", "dbtest", "python", "java"
        ]
        self.go_processes = []
        self.process_ids = []

        self._configure_processes()

    def execute(self):  # pylint: disable=too-many-branches,too-many-locals,too-many-statements
        """
        Execute hang analysis.

        1. Get a list of interesting processes
        2. Dump useful information or take core dumps
        """
        self._setup_logging()
        self._log_system_info()

        DebugExtractor.extract_debug_symbols(self.root_logger)
        dumpers = dumper.get_dumpers()

        processes = process_list.get_processes(self.process_ids, self.interesting_processes,
                                               self.options.process_match, self.root_logger)

        max_dump_size_bytes = int(self.options.max_core_dumps_size) * 1024 * 1024

        # Dump python processes by signalling them. The resmoke.py process will generate
        # the report.json, when signalled, so we do this before attaching to other processes.
        for (pid, process_name) in [(p, pn) for (p, pn) in processes if pn.startswith("python")]:
            # On Windows, we set up an event object to wait on a signal. For Cygwin, we register
            # a signal handler to wait for the signal since it supports POSIX signals.
            if _IS_WINDOWS:
                self.root_logger.info("Calling SetEvent to signal python process %s with PID %d",
                                      process_name, pid)
                signal_event_object(self.root_logger, pid)
            else:
                self.root_logger.info("Sending signal SIGUSR1 to python process %s with PID %d",
                                      process_name, pid)
                signal_process(self.root_logger, pid, signal.SIGUSR1)

        trapped_exceptions = []

        # Dump all processes, except python & java.
        for pinfo in [pinfo for pinfo in processes
                                    if not re.match("^(java|python)", pinfo.name)]:
            process_logger = get_process_logger(self.options.debugger_output, pinfo)
            try:
                dumpers.dbg.dump_info(
                    self.root_logger, process_logger, pinfo, self.options.dump_core
                    and check_dump_quota(max_dump_size_bytes, dumpers.dbg.get_dump_ext()))
            except Exception as err:  # pylint: disable=broad-except
                self.root_logger.info("Error encountered when invoking debugger %s", err)
                trapped_exceptions.append(traceback.format_exc())

        # Dump java processes using jstack.
        for pinfo in [pinfo for pinfo in processes if pinfo.name.startswith("java")]:
            process_logger = get_process_logger(self.options.debugger_output, pinfo)
            try:
                dumpers.jstack.dump_info(self.root_logger, pinfo.pid)
            except Exception as err:  # pylint: disable=broad-except
                self.root_logger.info("Error encountered when invoking debugger %s", err)
                trapped_exceptions.append(traceback.format_exc())

        # Signal go processes to ensure they print out stack traces, and die on POSIX OSes.
        # On Windows, this will simply kill the process since python emulates SIGABRT as
        # TerminateProcess.
        # Note: The stacktrace output may be captured elsewhere (i.e. resmoke).
        for pinfo in [pinfo for pinfo in processes if pinfo.name in self.go_processes]:
            self.root_logger.info("Sending signal SIGABRT to go process %s with PID %d",
                                  pinfo.name, pinfo.pid)
            signal_process(self.root_logger, pinfo.pid, signal.SIGABRT)

        self.root_logger.info("Done analyzing all processes for hangs")

        for exception in trapped_exceptions:
            self.root_logger.info(exception)
        if trapped_exceptions:
            sys.exit(1)

    def _configure_processes(self):
        if self.options.debugger_output is None:
            self.options.debugger_output = ['stdout']

        if self.options.process_ids is not None:
            # self.process_ids is an int list of PIDs
            self.process_ids = [int(pid) for pid in self.options.process_ids.split(',')]

        if self.options.process_names is not None:
            self.interesting_processes = self.options.process_names.split(',')

        if self.options.go_process_names is not None:
            self.go_processes = self.options.go_process_names.split(',')
            self.interesting_processes += self.go_processes

    def _setup_logging(self):
        self.root_logger = logging.Logger("hang_analyzer", level=logging.DEBUG)

        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(fmt="%(message)s"))
        self.root_logger.addHandler(handler)

        self.root_logger.info("Python Version: %s", sys.version)
        self.root_logger.info("OS: %s", platform.platform())

    def _log_system_info(self):
        try:
            if _IS_WINDOWS or sys.platform == "cygwin":
                distro = platform.win32_ver()
                self.root_logger.info("Windows Distribution: %s", distro)
            else:
                distro = platform.linux_distribution()
                self.root_logger.info("Linux Distribution: %s", distro)

        except AttributeError:
            self.root_logger.warning("Cannot determine Linux distro since Python is too old")

        try:
            uid = os.getuid()
            self.root_logger.info("Current User: %s", uid)
            current_login = os.getlogin()
            self.root_logger.info("Current Login: %s", current_login)
        except OSError:
            self.root_logger.warning("Cannot determine Unix Current Login")
        except AttributeError:
            self.root_logger.warning(
                "Cannot determine Unix Current Login, not supported on Windows")
