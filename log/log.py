# -*- coding: utf-8 -*-

__author__ = 'Dean'

import sys
import os
import logging

if __name__ == '__main__' :
    if len( sys.argv ) != 4 and len( sys.argv ) != 6:
        exit( -1 )
    logging.basicConfig( level=logging.DEBUG,
                        format='%(asctime)s %(message)s',
                        datefmt='%a, %d %b %Y %H:%M:%S',
                        filename = sys.argv[1] ,
                        filemode = sys.argv[2] )
    if len( sys.argv ) == 6:
        strFile = sys.argv[3]
        if len( os.path.split( sys.argv[3] ) ) == 2:
            strFile = os.path.split( sys.argv[3] )[1]
        logging.debug( '%s[%s] %s' % ( strFile , sys.argv[4] , sys.argv[5] ) )
    else:
        logging.debug( '%s' % sys.argv[3] )
    exit( 0 )
