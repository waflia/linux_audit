

class APIInfo():

    def __init__(self):
        self.modules = []
    
    def getModules(self):
        return self.modules
    
    def addModule(self, module):
        self.modules.append(module)
    
class Module():

    def __init__(self, info):
        info.addModule(self)
        

    
