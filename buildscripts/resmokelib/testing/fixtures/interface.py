"""Interface of the different fixtures for executing JSTests against."""

import os.path
import time
from enum import Enum
from collections import namedtuple
from typing import List

import pymongo
import pymongo.errors

from buildscripts.resmokelib import config
from buildscripts.resmokelib import errors
from buildscripts.resmokelib import logging
from buildscripts.resmokelib import multiversionconstants as multiversion
from buildscripts.resmokelib import utils
from buildscripts.resmokelib.utils import registry

_FIXTURES = {}  # type: ignore


class TeardownMode(Enum):
    """
    Enumeration representing different ways a fixture can be torn down.

    Each constant has the value of a Linux signal, even though the signal won't be used on Windows.
    This class is used because the 'signal' package on Windows has different values.
    """

    TERMINATE = 15
    KILL = 9
    ABORT = 6


def make_fixture(class_name, *args, **kwargs):
    """Provide factory function for creating Fixture instances."""

    if class_name not in _FIXTURES:
        raise ValueError("Unknown fixture class '%s'" % class_name)
    return _FIXTURES[class_name](*args, **kwargs)


class Fixture(object, metaclass=registry.make_registry_metaclass(_FIXTURES)):
    """Base class for all fixtures."""

    # We explicitly set the 'REGISTERED_NAME' attribute so that PyLint realizes that the attribute
    # is defined for all subclasses of Fixture.
    REGISTERED_NAME = "Fixture"

    _LAST_LTS_FCV = multiversion.LAST_LTS_FCV
    _LATEST_FCV = multiversion.LATEST_FCV
    _LAST_LTS_BIN_VERSION = multiversion.LAST_LTS_BIN_VERSION

    def __init__(self, logger, job_num, dbpath_prefix=None):
        """Initialize the fixture with a logger instance."""

        if not isinstance(logger, logging.Logger):
            raise TypeError("logger must be a Logger instance")

        if not isinstance(job_num, int):
            raise TypeError("job_num must be an integer")
        elif job_num < 0:
            raise ValueError("job_num must be a nonnegative integer")

        self.logger = logger
        self.job_num = job_num

        dbpath_prefix = utils.default_if_none(config.DBPATH_PREFIX, dbpath_prefix)
        dbpath_prefix = utils.default_if_none(dbpath_prefix, config.DEFAULT_DBPATH_PREFIX)
        self._dbpath_prefix = os.path.join(dbpath_prefix, "job{}".format(self.job_num))

    def pids(self):
        """Return any pids owned by this fixture."""
        raise NotImplementedError("pids must be implemented by Fixture subclasses %s" % self)

    def setup(self):
        """Create the fixture."""
        pass

    def await_ready(self):
        """Block until the fixture can be used for testing."""
        pass

    def teardown(self, finished=False, mode=None):  # noqa
        """Destroy the fixture.

        The fixture's logging handlers are closed if 'finished' is true,
        which should happen when setup() won't be called again.

        Raises:
            errors.ServerFailure: If the teardown is not successful.
        """

        try:
            self._do_teardown(mode=mode)
        finally:
            if finished:
                for handler in self.logger.handlers:
                    # We ignore the cancellation token returned by close_later() since we always
                    # want the logs to eventually get flushed.
                    logging.flush.close_later(handler)

    def _do_teardown(self, mode=None):  # noqa
        """Destroy the fixture.

        This method must be implemented by subclasses.

        Raises:
            errors.ServerFailure: If the teardown is not successful.
        """
        pass

    def is_running(self):  # pylint: disable=no-self-use
        """Return true if the fixture is still operating and more tests and can be run."""
        return True

    def get_node_info(self): # pylint: disable=no-self-use
        """Return a list of NodeInfo objects."""
        return []

    def get_dbpath_prefix(self):
        """Return dbpath prefix."""
        return self._dbpath_prefix

    def get_internal_connection_string(self):
        """Return the connection string for this fixture.

        This is NOT a driver connection string, but a connection string of the format
        expected by the mongo::ConnectionString class.
        """
        raise NotImplementedError(
            "get_internal_connection_string must be implemented by Fixture subclasses")

    def get_driver_connection_url(self):
        """Return the mongodb connection string as defined below.

        https://docs.mongodb.com/manual/reference/connection-string/
        """
        raise NotImplementedError(
            "get_driver_connection_url must be implemented by Fixture subclasses")

    def mongo_client(self, read_preference=pymongo.ReadPreference.PRIMARY, timeout_millis=30000):
        """Return a pymongo.MongoClient connecting to this fixture with specified 'read_preference'.

        The PyMongo driver will wait up to 'timeout_millis' milliseconds
        before concluding that the server is unavailable.
        """

        kwargs = {"connectTimeoutMS": timeout_millis}
        if pymongo.version_tuple[0] >= 3:
            kwargs["serverSelectionTimeoutMS"] = timeout_millis
            kwargs["connect"] = True

        return pymongo.MongoClient(host=self.get_driver_connection_url(),
                                   read_preference=read_preference, **kwargs)

    def __str__(self):
        return "%s (Job #%d)" % (self.__class__.__name__, self.job_num)

    def __repr__(self):
        return "%r(%r, %r)" % (self.__class__.__name__, self.logger, self.job_num)


class ReplFixture(Fixture):
    """Base class for all fixtures that support replication."""

    REGISTERED_NAME = registry.LEAVE_UNREGISTERED  # type: ignore

    AWAIT_REPL_TIMEOUT_MINS = 5
    AWAIT_REPL_TIMEOUT_FOREVER_MINS = 24 * 60

    def get_primary(self):
        """Return the primary of a replica set."""
        raise NotImplementedError("get_primary must be implemented by ReplFixture subclasses")

    def get_secondaries(self):
        """Return a list containing the secondaries of a replica set."""
        raise NotImplementedError("get_secondaries must be implemented by ReplFixture subclasses")

    def retry_until_wtimeout(self, insert_fn):
        """Retry until wtimeout reached.

        Given a callback function representing an insert operation on
        the primary, handle any connection failures, and keep retrying
        the operation for up to 'AWAIT_REPL_TIMEOUT_MINS' minutes.

        The insert operation callback should take an argument for the
        number of remaining seconds to provide as the timeout for the
        operation.
        """

        deadline = time.time() + ReplFixture.AWAIT_REPL_TIMEOUT_MINS * 60

        while True:
            try:
                remaining = deadline - time.time()
                insert_fn(remaining)
                break
            except pymongo.errors.ConnectionFailure:
                remaining = deadline - time.time()
                if remaining <= 0.0:
                    message = "Failed to connect to {} within {} minutes".format(
                        self.get_driver_connection_url(), ReplFixture.AWAIT_REPL_TIMEOUT_MINS)
                    self.logger.error(message)
                    raise errors.ServerFailure(message)
            except pymongo.errors.WTimeoutError:
                message = "Replication of write operation timed out."
                self.logger.error(message)
                raise errors.ServerFailure(message)
            except pymongo.errors.PyMongoError as err:
                message = "Write operation on {} failed: {}".format(
                    self.get_driver_connection_url(), err)
                raise errors.ServerFailure(message)


class NoOpFixture(Fixture):
    """A Fixture implementation that does not start any servers.

    Used when the MongoDB deployment is started by the JavaScript test itself with MongoRunner,
    ReplSetTest, or ShardingTest.
    """

    REGISTERED_NAME = "NoOpFixture"

    def pids(self):
        """:return: any pids owned by this fixture (none for NopFixture)."""
        return []

    def mongo_client(self, read_preference=None, timeout_millis=None):
        """Return the mongo_client connection."""
        raise NotImplementedError("NoOpFixture does not support a mongo_client")

    def get_internal_connection_string(self):
        """Return the internal connection string."""
        return None

    def get_driver_connection_url(self):
        """Return the driver connection URL."""
        return None


class FixtureTeardownHandler(object):
    """A helper class used to teardown nodes inside a cluster and keep track of errors."""

    def __init__(self, logger):
        """Initialize a FixtureTeardownHandler.

        Args:
            logger: A logger to use to log teardown activity.
        """
        self._logger = logger
        self._success = True
        self._message = None

    def was_successful(self):
        """Indicate whether the teardowns performed by this instance were all successful."""
        return self._success

    def get_error_message(self):
        """Retrieve the combined error message for all the teardown failures.

        Return None if all the teardowns were successful.
        """
        return self._message

    def teardown(self, fixture, name, mode=None):  # noqa: D406,D407,D411,D413
        """Tear down the given fixture and log errors instead of raising a ServerFailure exception.

        Args:
            fixture: The fixture to tear down.
            name: The name of the fixture.
        Returns:
            True if the teardown is successful, False otherwise.
        """
        try:
            self._logger.info("Stopping %s...", name)
            fixture.teardown(mode=mode)
            self._logger.info("Successfully stopped %s.", name)
            return True
        except errors.ServerFailure as err:
            msg = "Error while stopping {}: {}".format(name, err)
            self._logger.warning(msg)
            self._add_error_message(msg)
            self._success = False
            return False

    def _add_error_message(self, message):
        if not self._message:
            self._message = message
        else:
            self._message = "{} - {}".format(self._message, message)

def create_fixture_table(fixture):
    """Get fixture node info, make it a pretty table. Return it or None if fixture is invalid target."""
    info: List[NodeInfo] = fixture.get_node_info()
    if not info:
        return None

    columns = {}
    longest = {}
    for key in NodeInfo._fields:
        longest[key] = len(key)
        columns[key] = []
        for node in info:
            value = str(getattr(node, key))
            columns[key].append(value)
            longest[key] = max(longest[key], len(value))

    def horizontal_separator():
        row = ""
        for key in columns:
            row += "+" + "-" * (longest[key])
        row += "+"
        return row

    def title_row():
        row = ""
        for key in columns:
            row += "|" + key + " " * (longest[key] - len(key))
        row += "|"
        return row

    def data_row(i):
        row = ""
        for key in columns:
            row += "|" + columns[key][i] + " " * (longest[key] - len(columns[key][i]))
        row += "|"
        return row

    table = "\n"
    table += horizontal_separator() + "\n"
    table += title_row() + "\n"
    table += horizontal_separator() + "\n"
    for i in range(len(info)):
        table += data_row(i) + "\n"
    table += horizontal_separator()

    return table

# Represents a row in a node info table.
NodeInfo = namedtuple('NodeInfo', ['name', 'port', 'pid'])
