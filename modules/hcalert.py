
class Alert:
    id = 0
    def __init__(self,atype,aid=-1,msg="",misc={}):
        if aid == -1:
            id += 1
            self.aid=id
        else:
            self.aid=aid
        self.msg=msg
        self.atype=atype
        self.misc=misc


class ShellcodeAlert(Alert):
    def __init__(self,aid=-1,msg="Shellcode Detected",misc={},shellcode=""):
        Alert.__init__(self,"ALERT_SHELLCODE",aid,msg,misc)
        self.shellcode = shellcode;

class HeapsprayAlert(Alert):
    def __init__(self,aid=-1,msg="",misc={},sledgechar='\x90',entropy=-1):
        Alert.__init__(self,"ALERT_HEAPSPRAY",aid,msg,misc)
