from io import TextIOWrapper
import sys
import threading

class Fill_OutputFile:
    file: TextIOWrapper
    lock_OutputFile:any
    def __init__(self, file:TextIOWrapper):
        self.file = file
        self.lock_OutputFile = threading.Lock()  #used to read/write in output file

    def raise_exception(self,e:Exception):
        print('Main has finished with errors '+str(e))
        self.writeOutputFile(str(e))
        sys.exit()

    def writeOutputFile(self,s:str):
        self.lock_OutputFile.acquire()    
        self.file.write(threading.current_thread().name+ ' ' + s + '\n')  
        self.lock_OutputFile.release()