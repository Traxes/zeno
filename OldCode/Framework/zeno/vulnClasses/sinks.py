"""Sink Module

Handles the Sinks in one place

Returns:
    [type] -- [description]
"""

from sink_modules.bufferOverflow import *


class Sinks(object):
    """[summary]
    # TODO
    Arguments:
        object {[type]} -- [description]

    Returns:
        [type] -- [description]
    """

    def __init__(self):
        self.sinks = [
            BufferOverflow()
        ]
        self.generator = iter(self.sinks)

    def get(self):
        """Get the next Sink
        # TODO
        Returns:
            Object -- [description]
        """

        try:
            return next(self.generator)
        except StopIteration:
            return None
        except:
            print("ERROR")
