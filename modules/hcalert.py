
class Alert:
    def __init__(self,atype,aid=0,msg="",misc={}):
        self.aid=aid
        self.msg=msg
        self.atype=atype
        self.misc=misc


class ShellcodeAlert(Alert):
    def __init__(self,atype,aid=0,msg="",misc={}):
        Alert.__init__(self,atype,aid,msg,misc)

class HeapsprayAlert(Alert):
    def __init__(self,atype,aid=0,msg="",misc={}):
        Alert.__init__(self,atype,aid,msg,misc)
