import logging
import logging.config
import logging.handlers


class ZigbeeIDSLogger(object):

    def __init__(self):
        self.idslogger = logging.getLogger(__name__)
        self.idslogger.setLevel(logging.DEBUG)
        self.logformat = logging.Formatter('%(asctime)s - %(name)s - '
                                           '%(levelname)s - %(message)s')
        self.logging_levels = {
            10: 'debug',
            20: 'info',
            30: 'warning',
            40: 'error',
            50: 'critical'
        }

    def CreateLogHandlers(self):
        consolelog = logging.StreamHandler()
        consolelog.setLevel(logging.WARNING)
        consolelog.setFormatter(self.logformat)

        filelog = logging.FileHandler('/var/log/ZigbeeIDS.log', mode='a')
        filelog.setLevel(logging.DEBUG)
        filelog.setFormatter(self.logformat)

        self.idslogger.addHandler(filelog)
        self.idslogger.addHandler(consolelog)

    def ConsoleHandler(self, logmsg):
        if self.logging_levels[logmsg[0]] == 'warning':
            self.idslogger.warning(logmsg[1])
        elif self.logging_levels[logmsg[0]] == 'error':
            self.idslogger.error(logmsg[1])
        elif self.logging_levels[logmsg[0]] == 'critical':
            self.idslogger.critical(logmsg[1])

    def FileHandler(self, logmsg):
        if self.logging_levels[logmsg[0]] == 'info':
            self.idslogger.info(logmsg[1])
        elif self.logging_levels[logmsg[0]] == 'debug':
            self.idslogger.debug(logmsg[1])
