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

_REGISTRY: dict = {}


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
    """Create a child logger of the executor logger with the name "resmoke"."""
    logger = logging.Logger("resmoke")
    logger.parent = EXECUTOR_LOGGER
    return logger


def new_job_logger(test_kind, job_num):
    """Create a new logger for a given job thread."""
    name = "executor:%s:job%d" % (test_kind, job_num)
    logger = logging.Logger(name)
    logger.parent = EXECUTOR_LOGGER
    _prepare_build_id(job_num)

    return logger


# Fixture loggers


def new_fixture_logger(fixture_class, job_num):
    """Create a logger for a particular fixture class."""
    name = "%s:job%d" % (fixture_class, job_num)
    logger = logging.Logger(name)
    logger.parent = FIXTURE_LOGGER
    _add_build_logger_handler(logger, job_num)

    return logger


def new_fixture_node_logger(fixture_class, job_num, node_name, fixture_logger):
    """Create a logger for a particular element in a multi-process fixture.."""
    name = "%s:job%d:%s" % (fixture_class, job_num, node_name)
    logger = logging.Logger(name)
    logger.parent = fixture_logger
    return logger


# Test loggers


def new_testqueue_logger(test_kind):
    """Create a new test queue logger that associates the test kind to tests."""
    logger = logging.Logger(name=test_kind)
    logger.parent = TESTS_LOGGER
    return logger


#pylint: disable=too-many-arguments
def new_test_logger(test_shortname, test_basename, command, parent, job_num, job_logger):
    """Create a new test logger that will be a child of the given parent."""
    name = "%s:%s" % (parent.name, test_shortname)
    logger = logging.Logger(name)
    logger.parent = parent

    (test_id, url) = _get_test_endpoint(job_num, test_basename, command, job_logger)
    _add_build_logger_handler(logger, job_num, test_id)
    return (logger, url)


def new_test_thread_logger(parent, test_kind, thread_id):
    """Create a new test thread logger that will be the child of the given parent."""
    logger = logging.Logger("%s:%s" % (test_kind, thread_id))
    logger.parent = parent
    return logger


def new_hook_logger(hook_class, fixture_logger, job_num):
    """Create a new hook logger from a given fixture logger."""
    name = "{}:job{:d}".format(hook_class, job_num)
    logger = logging.Logger(name)
    logger.parent = fixture_logger
    return logger


# Util methods


def _add_handler(logger, handler_info, formatter):
    """Add non-buildlogger handlers to a logger based on configuration."""
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


def _get_buildlogger_handler_info(logger_info):
    """Return the buildlogger handler information if it exists, and None otherwise."""
    for handler_info in logger_info["handlers"]:
        handler_info = handler_info.copy()
        if handler_info.pop("class") == "buildlogger":
            return handler_info
    return None


def _add_build_logger_handler(logger, job_num, test_id=None):
    """Add a new buildlogger handler to a logger."""
    build_id = _REGISTRY[job_num]
    logger_info = config.LOGGING_CONFIG[TESTS_LOGGER_NAME]
    handler_info = _get_buildlogger_handler_info(logger_info)
    if handler_info is not None:
        if test_id is not None:
            handler = BUILDLOGGER_SERVER.get_test_handler(build_id, test_id, handler_info)
        else:
            handler = BUILDLOGGER_SERVER.get_global_handler(build_id, handler_info)
        handler.setFormatter(_get_formatter(logger_info))
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


def _prepare_build_id(job_num):
    """Prepare the build ID for a given job num."""
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

    _REGISTRY[job_num] = build_id


def _get_test_endpoint(job_num, test_basename, command, meta_logger):
    """Get a new test endpoint for the buildlogger server."""
    test_id = None
    url = None
    build_id = _REGISTRY[job_num]
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
        meta_logger.info("Writing output of %s to %s.", test_basename, url)

    return (test_id, url)


def _get_formatter(logger_info):
    """Return formatter."""
    log_format = logger_info.get("format", _DEFAULT_FORMAT)
    return formatters.ISO8601Formatter(fmt=log_format)
