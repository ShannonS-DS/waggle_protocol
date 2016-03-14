import logging
import MySQLdb
from contextlib import contextmanager

logger = logging.getLogger(__name__)



class Mysql(object):
    """
    Waggle specifc MySQL library.
    
    Used by beehive-cert and beehive-sshd.
    """
    
    
    def __init__(self, host='localhost', user='', passwd='', db=''):

        self._host=host
        self._user=user
        self._passwd=passwd
        self._db=db
        


    @contextmanager
    def get_cursor(self, query):


        # using with does not work here
        db = MySQLdb.connect(  host=self._host,    
                                     user=self._user,       
                                     passwd=self._passwd,  
                                     db=self._db)
        cur = db.cursor()
        logger.debug("query: " + query)
        try:
            cur.execute(query)
            db.commit()
            logger.debug("query was successful")
        except Exception as e:
            logger.error("query failed: (%s) %s" % (str(type(e)), str(e) ) )
        
        yield cur
        
        cur.close()
        db.close()
        


    def query_all(self, query):
        """
        MySQL query that returns multiple results in form of a generator
        """
        with self.get_cursor(query) as cur:
            # get array:
            for row in cur.fetchall():
                yield row
                

    def query_one(self, query):
        """
        MySQL query that returns a single result
        """
        
        with self.get_cursor(query) as cur:
            return cur.fetchone()
        
        


    def find_port(self, node_id):
        row = self.query_one("SELECT reverse_ssh_port FROM nodes WHERE node_id='{0}'".format(node_id))
        
        if not row:
            return None
        
        try:
            port = int(row[0])
        except ValueError:
            logger.error("Could not parse port number %s" % (port)) 
            port = None  
    
        
            return port
        return None


    def createNewNode(self, node_id, description, port):
    #0000001e06200335
        self.query_one("INSERT INTO nodes (node_id, description, reverse_ssh_port) VALUES ('%s', '%s', %d)" % ( node_id, description, port ))
        
        
        