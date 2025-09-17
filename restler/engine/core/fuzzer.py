# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import threading
import time

import engine.core.driver as driver
import utils.logger as logger
import traceback

from engine.core.fuzzing_monitor import Monitor
from engine.core.requests import GrammarRequestCollection
from engine.errors import InvalidDictionaryException

class FuzzingThread(threading.Thread):
    """ Fuzzer thread class
    """
    def __init__(self, fuzzing_requests, checkers, fuzzing_jobs=1, garbage_collector=None):
        """ Constructor for the Fuzzer thread class

        @param fuzzing_requests: The collection of requests to fuzz
        @type  fuzzing_requests: FuzzingRequestCollection
        @param checkers: List of checker objects
        @type  checkers: List[Checker]

        """
        threading.Thread.__init__(self)

        self._fuzzing_requests = fuzzing_requests
        self._checkers = checkers
        self._fuzzing_jobs = fuzzing_jobs
        self._garbage_collector = garbage_collector
        self._num_total_sequences = 0
        self._exception = None
        
        logger.write_to_main(f"[FUZZER_THREAD] Initialized fuzzer thread")
        logger.write_to_main(f"[FUZZER_THREAD] Requests to fuzz: {fuzzing_requests.size}")
        logger.write_to_main(f"[FUZZER_THREAD] Active checkers: {len(checkers)}")
        logger.write_to_main(f"[FUZZER_THREAD] Fuzzing jobs: {fuzzing_jobs}")
        logger.write_to_main(f"[FUZZER_THREAD] Garbage collector enabled: {garbage_collector is not None}")

    @property
    def exception(self):
        return self._exception

    def run(self):
        """ Thread entrance - performs fuzzing
        """
        logger.write_to_main(f"[FUZZER_THREAD] Starting fuzzing thread execution")
        start_time = time.time()
        
        try:
            logger.write_to_main(f"[FUZZER_THREAD] Calling driver.generate_sequences()")
            self._num_total_sequences = driver.generate_sequences(
                self._fuzzing_requests, self._checkers, self._fuzzing_jobs,
                self._garbage_collector
            )
            
            end_time = time.time()
            elapsed_time = end_time - start_time
            logger.write_to_main(f"[FUZZER_THREAD] Fuzzing completed successfully")
            logger.write_to_main(f"[FUZZER_THREAD] Total sequences generated: {self._num_total_sequences}")
            logger.write_to_main(f"[FUZZER_THREAD] Total execution time: {elapsed_time:.2f} seconds")

            # At the end of everything print out any request that were never
            # rendered (because they never had valid constraints).
            logger.write_to_main(f"[FUZZER_THREAD] Generating final rendering statistics")
            logger.print_request_rendering_stats_never_rendered_requests(
                self._fuzzing_requests,
                GrammarRequestCollection().candidate_values_pool,
                Monitor()
            )
        except InvalidDictionaryException as e:
            logger.write_to_main(f"[FUZZER_THREAD] InvalidDictionaryException caught: {e}")
            pass
        except Exception as err:
            end_time = time.time()
            elapsed_time = end_time - start_time
            logger.write_to_main(f"[FUZZER_THREAD] Exception occurred after {elapsed_time:.2f} seconds")
            logger.write_to_main(f"[FUZZER_THREAD] Exception details: {str(err)}")
            self._exception = traceback.format_exc()
            logger.write_to_main(f"[FUZZER_THREAD] Full traceback: {self._exception}")

    def join(self, *args):
        """ Overrides thread join function

        @return: The total number of sequences from the fuzzing run
        @rtype : Int

        """
        logger.write_to_main(f"[FUZZER_THREAD] Joining fuzzer thread")
        threading.Thread.join(self, *args)
        logger.write_to_main(f"[FUZZER_THREAD] Thread joined successfully, returning {self._num_total_sequences} total sequences")
        return self._num_total_sequences
