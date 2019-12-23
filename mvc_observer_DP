class observer3:
  def __init__(self):
    self.studentView = studentView()

  def notifyObserver(self,t,n,r):
      print(t)
      self.studentView.printStudeDetails(n,r)


 

class studentModel(observer3):
  def __init__(self,name = "", rollnumber = ""):
    self.name= name
    self.rollnumber = rollnumber
    self.observ = {"name":"empty","r_number":"empty"}
    self.obObject= observer3()

  
  def setName(self, name):
    if self.observ["name"] != name and self.observ["name"] !="empty":
      
      valu = "\n\n\n[*] update: name from ** {} ** to  ** {} ** \n==> after ".format(self.name,name)
      self.obObject.notifyObserver(valu,name,self.rollnumber)

    self.observ["name"] = name
    self.name = name




  def getName(self):
    return self.name
  
  def setrollnumber(self, rn):

    if self.observ["r_number"] != rn and self.observ["r_number"] !="empty":
        valu = "\n\n [*]update: Rollnumber from ** {} ** to ** {} ** \n ==>after e ".format(self.rollnumber,rn)
        self.obObject.notifyObserver(valu,rn,self.rollnumber)

    self.rollnumber = rn
    self.observ["r_number"] = rn


  def getrollnumber(self):
    return self.rollnumber


class studentView:
  def printStudeDetails(self, name, rolln):
    print("student name = {},student rollnumber ={}".format(name,rolln) )

class studentcontroler:
  def __init__(self,model,view):
    self.model = model
    self.view  = view

  def setname(self,name):
    self.model.setName(name)
  def getName(self):
    self.model.getName()

  def setrollnumber(self,rn):
    self.model.setrollnumber(rn)
  def getrollnumber(self):
    self.model.getrollnumber()

  def printDetails(self):
    self.view.printStudeDetails(self.model.getName(),self.model.getrollnumber())


model = studentModel()
view  = studentView()

controler = studentcontroler(model,view)

controler.setname("first")
controler.setrollnumber("33")
controler.printDetails()
controler.setname("second_name")
controler.setname("third name")
controler.setrollnumber("333")

# controler.printDetails()
