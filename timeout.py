import signal
# taken from https://github.com/angr/angr/issues/682


class TimeoutError(Exception):
    pass


def is_debugging():
    pass


class timeout:

    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        if not is_debugging():  # Timeouts should be disabled while debugging.
            print("[-] Timeout...")
            raise TimeoutError(self.error_message)
        print('TimeoutError was not raised due to debug is ongoing!')

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)
