"""Module to hold the logger instances themselves."""

import logging
import sys

from . import buildlogger
from . import formatters
from .. import errors
from .. import config

_DEFAULT_FORMAT = "[%(name)s] %(message)s"

BUILDLOGGER_SERVER = None

# Executor logger logs information from the testing infrastructure.
EXECUTOR_LOGGER_NAME = "executor"

# Fixture logger logs information related to fixtures.
FIXTURE_LOGGER_NAME = "fixture"

# Test logger logs info from actual client-side tests.
TESTS_LOGGER_NAME = "tests"

EXECUTOR_LOGGER = None
FIXTURE_LOGGER = None
TESTS_LOGGER = None

REGISTRY = {}

def _build_logger_server():
    """Create and return a new BuildloggerServer.

    This occurs if "buildlogger" is configured as one of the handler class in the configuration,
    return None otherwise.
    """
    for logger_name in (FIXTURE_LOGGER_NAME, TESTS_LOGGER_NAME):
        logger_info = config.LOGGING_CONFIG[logger_name]
        for handler_info in logger_info["handlers"]:
            if handler_info["class"] == "buildlogger":
                return buildlogger.BuildloggerServer()
    return None


def configure_loggers():
    """Configure the loggers."""
    buildlogger.BUILDLOGGER_FALLBACK = logging.Logger("buildlogger")
    # The 'buildlogger' prefix is not added to the fallback logger since the prefix of the original
    # logger will be there as part of the logged message.
    buildlogger.BUILDLOGGER_FALLBACK.addHandler(
        _fallback_buildlogger_handler(include_logger_name=False))

    global BUILDLOGGER_SERVER  # pylint: disable=global-statement
    BUILDLOGGER_SERVER = _build_logger_server()

    global TESTS_LOGGER  # pylint: disable=global-statement
    TESTS_LOGGER = new_root_logger(TESTS_LOGGER_NAME)
    global FIXTURE_LOGGER  # pylint: disable=global-statement
    FIXTURE_LOGGER = new_root_logger(FIXTURE_LOGGER_NAME)
    global EXECUTOR_LOGGER  # pylint: disable=global-statement
    EXECUTOR_LOGGER = new_root_logger(EXECUTOR_LOGGER_NAME)


def new_root_logger(name):
    """
    Create and configure a new root logger.

    :param name: The name of the new root logger.
    """
    if name not in config.LOGGING_CONFIG:
        raise ValueError("Logging configuration should contain the %s component" % name)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger_info = config.LOGGING_CONFIG[name]
    formatter = _get_formatter(logger_info)

    for handler_info in logger_info.get("handlers", []):
        _add_handler(logger, handler_info, formatter)

    return logger


def new_resmoke_logger():
    """Create a child logger of this logger with the name "resmoke"."""
    logger = logging.Logger("resmoke")
    logger.parent = EXECUTOR_LOGGER
    return logger

def new_job_logger(test_kind, job_num):
    """Create a new child JobLogger."""

    name = "executor:%s:job%d" % (test_kind, job_num)
    logger = logging.Logger(name)
    logger.parent = EXECUTOR_LOGGER

    # TODO: Maybe do this in-place when needed rather than when the job logger is constructed.
    if BUILDLOGGER_SERVER:
        # If we're configured to log messages to the buildlogger server, then request a new
        # build_id for this job.
        build_id = BUILDLOGGER_SERVER.new_build_id("job%d" % job_num)
        if not build_id:
            buildlogger.set_log_output_incomplete()
            raise errors.LoggerRuntimeConfigError(
                "Encountered an error configuring buildlogger for job #{:d}: Failed to get a"
                " new build_id".format(job_num))

        url = BUILDLOGGER_SERVER.get_build_log_url(build_id)
        EXECUTOR_LOGGER.info("Writing output of job #%d to %s.", job_num, url)
    else:
        build_id = None

    REGISTRY[job_num] = build_id

    return logger

def new_fixture_logger(fixture_class, job_num):
    """Create a new fixture logger that will be a child of the "fixture" root logger."""
    return FixtureLogger(fixture_class, job_num, REGISTRY[job_num])

def new_test_logger(test_shortname, test_basename, command, parent, job_num, job_logger):
    """Create a new test logger that will be a child of the given parent."""
    test_id = None
    url = None
    build_id = REGISTRY[job_num]
    if build_id:
        # If we're configured to log messages to the buildlogger server, then request a new
        # test_id for this test.
        test_id = BUILDLOGGER_SERVER.new_test_id(build_id, test_basename, command)
        if not test_id:
            buildlogger.set_log_output_incomplete()
            raise errors.LoggerRuntimeConfigError(
                "Encountered an error configuring buildlogger for test {}: Failed to get a new"
                " test_id".format(test_basename))

        url = BUILDLOGGER_SERVER.get_test_log_url(build_id, test_id)
        job_logger.info("Writing output of %s to %s.", test_basename, url)

    name = "%s:%s" % (parent.name, test_shortname)
    logger = logging.Logger(name)
    logger.parent = parent
    _add_build_logger_handler(logger, build_id, test_id)

    return (logger, url)

def new_test_thread_logger(parent, test_kind, thread_id):
    """Create a new child test thread logger."""
    logger = logging.Logger("%s:%s" % (test_kind, thread_id))
    logger.parent = parent
    return logger

def new_testqueue_logger(test_kind):
    """Create a new TestQueueLogger that will be a child of the "tests" root logger."""
    logger = logging.Logger(name=test_kind)
    logger.parent = TESTS_LOGGER

    return logger

def new_hook_logger(hook_class, fixture_logger):
    """Create a new child hook logger."""
    return HookLogger(hook_class, fixture_logger)

class FixtureLogger(logging.Logger):
    """FixtureLogger class."""

    def __init__(self, fixture_class, job_num, build_id):
        """Initialize a FixtureLogger.

        :param fixture_class: the name of the fixture class.
        :param job_num: the number of the job the fixture is running on.
        :param build_id: the build logger build id, if any.
        """
        name = "%s:job%d" % (fixture_class, job_num)
        logging.Logger.__init__(self, name)

        self.parent = FIXTURE_LOGGER
        self.fixture_class = fixture_class
        self.job_num = job_num
        self._add_build_logger_handler(build_id)

    def _add_build_logger_handler(self, build_id):
        logger_info = config.LOGGING_CONFIG[FIXTURE_LOGGER_NAME]
        handler_info = _get_buildlogger_handler_info(logger_info)
        if handler_info is not None:
            handler = BUILDLOGGER_SERVER.get_global_handler(build_id, handler_info)
            handler.setFormatter(_get_formatter(logger_info))
            self.addHandler(handler)

    def new_fixture_node_logger(self, node_name):
        """Create a new child FixtureNodeLogger."""
        return FixtureNodeLogger(self.fixture_class, self.job_num, node_name, self)


class FixtureNodeLogger(logging.Logger):
    """FixtureNodeLogger class."""

    def __init__(self, fixture_class, job_num, node_name, fixture_logger):
        """Initialize a FixtureNodeLogger.

        :param fixture_class: the name of the fixture implementation class.
        :param job_num: the number of the job the fixture is running on.
        :param node_name: the node display name.
        :param fixture_logger: the parent fixture logger.
        """
        name = "%s:job%d:%s" % (fixture_class, job_num, node_name)
        logging.Logger.__init__(self, name)

        self.parent = fixture_logger
        self.fixture_class = fixture_class
        self.job_num = job_num
        self.node_name = node_name

    def new_fixture_node_logger(self, node_name):
        """Create a new child FixtureNodeLogger."""
        return FixtureNodeLogger(self.fixture_class, self.job_num,
                                 "%s:%s" % (self.node_name, node_name), self)


class HookLogger(logging.Logger):
    """HookLogger class."""

    def __init__(self, hook_class, fixture_logger):
        """Initialize a HookLogger.

        :param hook_class: the hook's name (e.g. CheckReplDBHash, ValidateCollections, etc.).
        :param fixture_logger: the logger for the fixtures logs.
        :param tests_root_logger: the root logger for the tests logs.
        """
        name = "{}:job{:d}".format(hook_class, fixture_logger.job_num)
        logging.Logger.__init__(self, name)
        self.parent = fixture_logger

        self.test_case_logger = logging.Logger(name)
        self.test_case_logger.parent = TESTS_LOGGER


# Util methods


def _add_handler(logger, handler_info, formatter):
    handler_class = handler_info["class"]
    if handler_class == "logging.FileHandler":
        handler = logging.FileHandler(filename=handler_info["filename"], mode=handler_info.get(
            "mode", "w"))
    elif handler_class == "logging.NullHandler":
        handler = logging.NullHandler()
    elif handler_class == "logging.StreamHandler":
        handler = logging.StreamHandler(sys.stdout)
    elif handler_class == "buildlogger":
        return  # Buildlogger handlers are applied when creating specific child loggers
    else:
        raise ValueError("Unknown handler class '%s'" % handler_class)
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def _fallback_buildlogger_handler(include_logger_name=True):
    """Return a handler that writes to stderr."""
    if include_logger_name:
        log_format = "[fallback] [%(name)s] %(message)s"
    else:
        log_format = "[fallback] %(message)s"
    formatter = formatters.ISO8601Formatter(fmt=log_format)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    return handler


def _get_buildlogger_handler_info(logger_info):
    """Return the buildlogger handler information if it exists, and None otherwise."""
    for handler_info in logger_info["handlers"]:
        handler_info = handler_info.copy()
        if handler_info.pop("class") == "buildlogger":
            return handler_info
    return None

def _add_build_logger_handler(logger, build_id, test_id):
    logger_info = config.LOGGING_CONFIG[TESTS_LOGGER_NAME]
    handler_info = _get_buildlogger_handler_info(logger_info)
    if handler_info is not None:
        handler = BUILDLOGGER_SERVER.get_test_handler(build_id, test_id, handler_info)
        handler.setFormatter(_get_formatter(logger_info))
        logger.addHandler(handler)


def _get_formatter(logger_info):
    """Return formatter."""
    log_format = logger_info.get("format", _DEFAULT_FORMAT)
    return formatters.ISO8601Formatter(fmt=log_format)
