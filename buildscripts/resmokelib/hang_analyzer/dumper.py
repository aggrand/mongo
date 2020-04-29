"""Tools to dump debug info for each OS."""
import os
import sys
import logging
import tempfile
import itertools
import subprocess
from distutils import spawn  # pylint: disable=no-name-in-module

from buildscripts.resmokelib import core

def get_dumpers():
    """Return OS-appropriate dumpers."""

    dbg = None
    jstack = None
    if sys.platform.startswith("linux"):
        dbg = GDBDumper()
        jstack = JstackDumper()
    elif sys.platform.startswith("sunos"):
        dbg = GDBDumper()
        jstack = JstackDumper()
    elif sys.platform == "win32" or sys.platform == "cygwin":
        dbg = WindowsDumper()
        jstack = JstackWindowsDumper()
    elif sys.platform == "darwin":
        dbg = LLDBDumper()
        jstack = JstackDumper()

    return [dbg, jstack]

class Dumper(object):
    """Abstract base class for all OS-specific dumpers."""

    def dump_info(  # pylint: disable=too-many-arguments,too-many-locals
            self, root_logger, logger, pid, process_name, take_dump):
        """
        Perform dump for a process.

        :param root_logger: Top-level logger
        :param logger: Logger to output dump info to
        :param pid: PID of the process to dump
        :param process_name: Name of the process to dump
        :param take_dump: Whether to take a core dump
        """
        raise NotImplementedError("dump_info must be implemented in OS-specific subclasses")

class WindowsDumper(Dumper):
    """WindowsDumper class."""

    @staticmethod
    def __find_debugger(logger, debugger):
        """Find the installed debugger."""
        # We are looking for c:\Program Files (x86)\Windows Kits\8.1\Debuggers\x64
        cdb = spawn.find_executable(debugger)
        if cdb is not None:
            return cdb
        from win32com.shell import shell, shellcon

        # Cygwin via sshd does not expose the normal environment variables
        # Use the shell api to get the variable instead
        root_dir = shell.SHGetFolderPath(0, shellcon.CSIDL_PROGRAM_FILESX86, None, 0)

        # Construct the debugger search paths in most-recent order
        debugger_paths = [os.path.join(root_dir, "Windows Kits", "10", "Debuggers", "x64")]
        for idx in reversed(range(0, 2)):
            debugger_paths.append(
                os.path.join(root_dir, "Windows Kits", "8." + str(idx), "Debuggers", "x64"))

        for dbg_path in debugger_paths:
            logger.info("Checking for debugger in %s", dbg_path)
            if os.path.exists(dbg_path):
                return os.path.join(dbg_path, debugger)

        return None

    def dump_info(  # pylint: disable=too-many-arguments
            self, root_logger, logger, pid, process_name, take_dump):
        """Dump useful information to the console."""
        debugger = "cdb.exe"
        dbg = self.__find_debugger(root_logger, debugger)

        if dbg is None:
            root_logger.warning("Debugger %s not found, skipping dumping of %d", debugger, pid)
            return

        root_logger.info("Debugger %s, analyzing %s process with PID %d", dbg, process_name, pid)

        dump_command = ""
        if take_dump:
            # Dump to file, dump_<process name>.<pid>.mdmp
            dump_file = "dump_%s.%d.%s" % (os.path.splitext(process_name)[0], pid,
                                           self.get_dump_ext())
            dump_command = ".dump /ma %s" % dump_file
            root_logger.info("Dumping core to %s", dump_file)

        cmds = [
            ".symfix",  # Fixup symbol path
            ".symopt +0x10",  # Enable line loading (off by default in CDB, on by default in WinDBG)
            ".reload",  # Reload symbols
            "!peb",  # Dump current exe, & environment variables
            "lm",  # Dump loaded modules
            dump_command,
            "!uniqstack -pn",  # Dump All unique Threads with function arguments
            "!cs -l",  # Dump all locked critical sections
            ".detach",  # Detach
            "q"  # Quit
        ]

        call([dbg, '-c', ";".join(cmds), '-p', str(pid)], logger)

        root_logger.info("Done analyzing %s process with PID %d", process_name, pid)

    @staticmethod
    def get_dump_ext():
        """Return the dump file extension."""
        return "mdmp"


# LLDB dumper is for MacOS X
class LLDBDumper(Dumper):
    """LLDBDumper class."""

    @staticmethod
    def __find_debugger(debugger):
        """Find the installed debugger."""
        return find_program(debugger, ['/usr/bin'])

    def dump_info(  # pylint: disable=too-many-arguments,too-many-locals
            self, root_logger, logger, pid, process_name, take_dump):
        """Dump info."""
        debugger = "lldb"
        dbg = self.__find_debugger(debugger)

        if dbg is None:
            root_logger.warning("Debugger %s not found, skipping dumping of %d", debugger, pid)
            return

        root_logger.info("Debugger %s, analyzing %s process with PID %d", dbg, process_name, pid)

        lldb_version = callo([dbg, "--version"], logger)

        logger.info(lldb_version)

        # Do we have the XCode or LLVM version of lldb?
        # Old versions of lldb do not work well when taking commands via a file
        # XCode (7.2): lldb-340.4.119
        # LLVM - lldb version 3.7.0 ( revision )

        if 'version' not in lldb_version:
            # We have XCode's lldb
            lldb_version = lldb_version[lldb_version.index("lldb-"):]
            lldb_version = lldb_version.replace('lldb-', '')
            lldb_major_version = int(lldb_version[:lldb_version.index('.')])
            if lldb_major_version < 340:
                logger.warning("Debugger lldb is too old, please upgrade to XCode 7.2")
                return

        dump_command = ""
        if take_dump:
            # Dump to file, dump_<process name>.<pid>.core
            dump_file = "dump_%s.%d.%s" % (process_name, pid, self.get_dump_ext())
            dump_command = "process save-core %s" % dump_file
            root_logger.info("Dumping core to %s", dump_file)

        cmds = [
            "attach -p %d" % pid,
            "target modules list",
            "thread backtrace all",
            dump_command,
            "settings set interpreter.prompt-on-quit false",
            "quit",
        ]

        tf = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8')

        for cmd in cmds:
            tf.write(cmd + "\n")

        tf.flush()

        # Works on in MacOS 10.9 & later
        #call([dbg] +  list( itertools.chain.from_iterable([['-o', b] for b in cmds])), logger)
        call(['cat', tf.name], logger)
        call([dbg, '--source', tf.name], logger)

        root_logger.info("Done analyzing %s process with PID %d", process_name, pid)

    @staticmethod
    def get_dump_ext():
        """Return the dump file extension."""
        return "core"


# GDB dumper is for Linux & Solaris
class GDBDumper(Dumper):
    """GDBDumper class."""

    @staticmethod
    def __find_debugger(debugger):
        """Find the installed debugger."""
        return find_program(debugger, ['/opt/mongodbtoolchain/gdb/bin', '/usr/bin'])

    def dump_info(  # pylint: disable=too-many-arguments,too-many-locals
            self, root_logger, logger, pid, process_name, take_dump):
        """Dump info."""
        debugger = "gdb"
        dbg = self.__find_debugger(debugger)

        if dbg is None:
            logger.warning("Debugger %s not found, skipping dumping of %d", debugger, pid)
            return

        root_logger.info("Debugger %s, analyzing %s process with PID %d", dbg, process_name, pid)

        dump_command = ""
        if take_dump:
            # Dump to file, dump_<process name>.<pid>.core
            dump_file = "dump_%s.%d.%s" % (process_name, pid, self.get_dump_ext())
            dump_command = "gcore %s" % dump_file
            root_logger.info("Dumping core to %s", dump_file)

        call([dbg, "--version"], logger)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        root_logger.info("dir %s", script_dir)
        gdb_dir = os.path.join(script_dir, "gdb")
        mongo_script = os.path.join(gdb_dir, "mongo.py")
        mongo_printers_script = os.path.join(gdb_dir, "mongo_printers.py")
        mongo_lock_script = os.path.join(gdb_dir, "mongo_lock.py")

        source_mongo = "source %s" % mongo_script
        source_mongo_printers = "source %s" % mongo_printers_script
        source_mongo_lock = "source %s" % mongo_lock_script
        mongodb_dump_locks = "mongodb-dump-locks"
        mongodb_show_locks = "mongodb-show-locks"
        mongodb_uniqstack = "mongodb-uniqstack mongodb-bt-if-active"
        mongodb_waitsfor_graph = "mongodb-waitsfor-graph debugger_waitsfor_%s_%d.gv" % \
            (process_name, pid)
        mongodb_javascript_stack = "mongodb-javascript-stack"
        mongod_dump_sessions = "mongod-dump-sessions"
        mongodb_dump_mutexes = "mongodb-dump-mutexes"

        # The following MongoDB python extensions do not run on Solaris.
        if sys.platform.startswith("sunos"):
            source_mongo_lock = ""
            # SERVER-28234 - GDB frame information not available on Solaris for a templatized
            # function
            mongodb_dump_locks = ""

            # SERVER-28373 - GDB thread-local variables not available on Solaris
            mongodb_show_locks = ""
            mongodb_waitsfor_graph = ""
            mongodb_javascript_stack = ""
            mongod_dump_sessions = ""

        if not logger.mongo_process_filename:
            raw_stacks_commands = []
        else:
            base, ext = os.path.splitext(logger.mongo_process_filename)
            raw_stacks_filename = base + '_raw_stacks' + ext
            raw_stacks_commands = [
                'echo \\nWriting raw stacks to %s.\\n' % raw_stacks_filename,
                # This sends output to log file rather than stdout until we turn logging off.
                'set logging redirect on',
                'set logging file ' + raw_stacks_filename,
                'set logging on',
                'thread apply all bt',
                'set logging off',
            ]

        cmds = [
            "set interactive-mode off",
            "set print thread-events off",  # Suppress GDB messages of threads starting/finishing.
            "file %s" % process_name,  # Solaris must load the process to read the symbols.
            "attach %d" % pid,
            "info sharedlibrary",
            "info threads",  # Dump a simple list of commands to get the thread name
            "set python print-stack full",
        ] + raw_stacks_commands + [
            source_mongo,
            source_mongo_printers,
            source_mongo_lock,
            mongodb_uniqstack,
            # Lock the scheduler, before running commands, which execute code in the attached process.
            "set scheduler-locking on",
            dump_command,
            mongodb_dump_locks,
            mongodb_show_locks,
            mongodb_waitsfor_graph,
            mongodb_javascript_stack,
            mongod_dump_sessions,
            mongodb_dump_mutexes,
            "set confirm off",
            "quit",
        ]

        call([dbg, "--quiet", "--nx"] + list(
            itertools.chain.from_iterable([['-ex', b] for b in cmds])), logger)

        root_logger.info("Done analyzing %s process with PID %d", process_name, pid)

    @staticmethod
    def get_dump_ext():
        """Return the dump file extension."""
        return "core"

    @staticmethod
    def _find_gcore():
        """Find the installed gcore."""
        dbg = "/usr/bin/gcore"
        if os.path.exists(dbg):
            return dbg

        return None


# jstack is a JDK utility
class JstackDumper(Dumper):
    """JstackDumper class."""

    @staticmethod
    def __find_debugger(debugger):
        """Find the installed jstack debugger."""
        return find_program(debugger, ['/usr/bin'])

    def dump_info(self, root_logger, logger, pid, process_name):
        """Dump java thread stack traces to the console."""
        debugger = "jstack"
        jstack = self.__find_debugger(debugger)

        if jstack is None:
            logger.warning("Debugger %s not found, skipping dumping of %d", debugger, pid)
            return

        root_logger.info("Debugger %s, analyzing %s process with PID %d", jstack, process_name, pid)

        call([jstack, "-l", str(pid)], logger)

        root_logger.info("Done analyzing %s process with PID %d", process_name, pid)


# jstack is a JDK utility
class JstackWindowsDumper(Dumper):
    """JstackWindowsDumper class."""

    @staticmethod
    def dump_info(root_logger, pid):
        """Dump java thread stack traces to the logger."""

        root_logger.warning("Debugger jstack not supported, skipping dumping of %d", pid)

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

# TODO: Defined twice
def find_program(prog, paths):
    """Find the specified program in env PATH, or tries a set of paths."""
    for loc in paths:
        full_prog = os.path.join(loc, prog)
        if os.path.exists(full_prog):
            return full_prog

    return spawn.find_executable(prog)

# TODO: Defined twice
def callo(args, logger):
    """Call subprocess on args string."""
    logger.info("%s", str(args))

    return subprocess.check_output(args).decode('utf-8', 'replace')
