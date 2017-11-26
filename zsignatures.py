import sqlite3
from os import path
from datetime import datetime
from sys import exit
from datetime import datetime
from subprocess import check_output
import hashlib
from codecs import decode


class ZigbeeSignaturesDB(object):

    def __init__(self, database):

        if path.isfile(database):
            self.dbconn = sqlite3.connect(database)
            self.idscursor = self.dbconn.cursor()
        else:
            create_opt = raw_input('Signature DB not found... '
                                   'Creating new db (Y/N)?>')
            if create_opt.lower() == 'y':
                self.dbconn = sqlite3.connect(database)
                self.idscursor = self.dbconn.cursor()
            else:
                print 'Not usable DB given... Exiting!'
                exit(0)

    def CreateSignatureTables(self):

        self.idscursor.execute('''CREATE TABLE source_routing_signatures
                              (ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                              date TEXT,
                              src_short TEXT,
                              dst_short TEXT,
                              src_ext TEXT,
                              dst_ext TEXT,
                              signature TEXT)''')

        self.idscursor.execute('''CREATE TABLE m2one_routing_signatures
                              (ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                              date TEXT,
                              src_short TEXT,
                              src_ext TEXT,
                              signature TEXT)''')

    def CheckRRPatterns(self, pkt_attr, rrsignature):
        self.idscursor.execute('SELECT * FROM source_routing_signatures\
            WHERE signature = ?', (rrsignature,))
        signature_record = self.idscursor.fetchone()

        if signature_record is None:
            timestamp = datetime.now()
            pkt_tuple = (timestamp,
                         pkt_attr.nwk_address,
                         pkt_attr.l3_dest,
                         pkt_attr.l3_src_ext,
                         pkt_attr.l3_dst_ext,
                         rrsignature)
            self.idscursor.execute('INSERT INTO\
                source_routing_signatures (date, src_short, dst_short,\
                src_ext, dst_ext, signature) VALUES\
                (?, ?, ?, ?, ?, ?)', pkt_tuple)
            self.dbconn.commit()
            return (50, 'New signature {:s} for '
                        'malicious Route Record (RREP)'
                        ' - possible wormhole attack '
                        'from {:s}'.format(pkt_attr.nwk_address,
                                           rrsignature))
        elif signature_record is not None:
            return (50, 'Signature {:s} match for '
                        'malicious Route Record '
                        ' - possible wormhole attack '
                        'from {:s}'.format(pkt_attr.nwk_address,
                                           rrsignature))
        else:
            pass

    def CheckM2OPatterns(self, pkt_attr, m2osignature):
        self.idscursor.execute('SELECT * FROM m2one_routing_signatures \
                               WHERE signature = ?', (m2osignature,))
        signature_record = self.idscursor.fetchone()
        if signature_record is None:
            timestamp = datetime.now()
            pkt_tuple = (timestamp,
                         pkt_attr.l3_src,
                         pkt_attr.l3_ext_src,
                         m2osignature)
            self.idscursor.execute('INSERT INTO m2one_routing_signatures \
                                   (date, src_short, src_ext, signature) \
                                   VALUES (?,?,?,?)', pkt_tuple)
            self.dbconn.commit()
            return (50, 'New signature {:s} for '
                        'malicious RREQ many-to-one '
                        'possible sinkhole attack '
                        'from {:s}'.format(pkt_attr.nwk_address,
                                           m2osignature))
        elif signature_record is not None:
            return (50, 'Signature match {:s} for '
                        'malicious RREQ many-to-one '
                        'possible sinkhole attack '
                        'from {:s}'.format(pkt_attr.nwk_address,
                                           m2osignature))
