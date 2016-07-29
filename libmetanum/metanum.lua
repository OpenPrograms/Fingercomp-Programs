-- A library hacked by Zer0Galaxy,
-- the original version can be found here: http://pastebin.com/PsMFQame
-- I've stripped the comments written in Russian, and packaged the library.

local metanum,m_table

local function correct(mn)
  local e
  mn.mant,e=mn.mant:match("^0*(.-)(0*)$")
  mn.exp=mn.exp+#e
  if mn.mant=="" then mn.neg=false mn.exp=0 end
  return mn
end

local function getMant(op1,op2)
  local m1=op1.mant if op1.exp>op2.exp then m1=m1..string.rep("0",op1.exp-op2.exp) end
  local m2=op2.mant if op2.exp>op1.exp then m2=m2..string.rep("0",op2.exp-op1.exp) end
  if #m1>#m2 then m2=string.rep("0",#m1-#m2)..m2 end
  if #m2>#m1 then m1=string.rep("0",#m2-#m1)..m1 end
  return m1,m2
end

local function division(op1,op2,divprec)
  local dividend=metanum(op1)
  local divisor=metanum(op2)
  if divisor.mant=="" then return math.huge, 0/0 end
  local res={mant="0",neg= dividend.neg~=divisor.neg,exp=#dividend.mant+dividend.exp-#divisor.mant-divisor.exp, divprec=divprec}
  dividend.neg=false
  divisor.neg=false
  divisor.exp=divisor.exp+res.exp
  setmetatable(res,m_table)
  
  while dividend.mant~="" do
    if divisor>dividend then
	  res.mant=res.mant.."0"
	  res.exp=res.exp-1
	  if res.exp<0 and #res.mant>res.divprec then
	    if res.neg then return res+setmetatable({neg=true,mant="1",exp=res.exp+1},m_table) end
		break
	  end
	  dividend.exp=dividend.exp+1
	else
	  dividend=dividend-divisor
	  res.mant=res.mant:sub(1,-2)..(res.mant:byte(-1)-47)
	end
  end
  return correct(res)
end

m_table={
  __index={ divprec = 32,
    tonumber=function(self)
	  return tonumber(tostring(self))
	end,
	floor=function(self,n)
	  local res=metanum(self)
	  n=n or 0
	  if res.exp<-n then
	    res.mant=res.mant:sub(1,res.exp+n-1)
		res.exp=-n
		if res.neg then
		  local one=metanum("1")
		  one.exp=-n
		  return res-one
		end
	  end
	  return res
	end,
	abs=function(self)
	  local res=metanum(self)
	  res.neg=false
	  return res
	end,
	toexp=function(self)
	  if self.mant=="" then return 0 end
	  return self.mant:sub(1,1).."."..self.mant:sub(2).."e"..(#self.mant-1+math.floor(self.exp))
	end,
  },
  __tostring=function(self)
    local res
	if self.exp>=0 then res=self.mant..string.rep("0",self.exp)
	else
	  res=string.rep("0",1-self.exp-#self.mant)..self.mant
	  res=res:sub(1,self.exp-1).."."..res:sub(self.exp)
	end
	if res=="" then res="0" end
	if self.neg then res="-"..res end
	return res
  end,
  __unm=function(self)
    local res=metanum(self)
	res.neg=not res.neg
	return res
  end,
  __add=function(op1,op2)
    if getmetatable(op1)~=m_table then op1=metanum(op1) end
    if getmetatable(op2)~=m_table then op2=metanum(op2) end
	if op1.neg~=op2.neg then return op1-(-op2) end
	local res=metanum() res.neg=op1.neg
	local c=0
	local m1,m2=getMant(op1,op2)
	res.exp=math.min(op1.exp,op2.exp)
	for i=#m1,1,-1 do
	  c=m1:byte(i)+m2:byte(i)+c-96
	  res.mant=c%10 .. res.mant
	  c=math.floor(c/10)
	end
	res.mant=c .. res.mant
	return correct(res)
  end,
  __sub=function(op1,op2)
    if getmetatable(op1)~=m_table then op1=metanum(op1) end
    if getmetatable(op2)~=m_table then op2=metanum(op2) end
	if op1.neg~=op2.neg then return op1+(-op2) end
	local res=metanum() res.neg=op1.neg
	local c=0
	local m1,m2=getMant(op1,op2)
	res.exp=math.min(op1.exp,op2.exp)
	if m2>m1 then m1,m2 = m2,m1 res.neg=not res.neg end
	for i=#m1,1,-1 do
	  c=m1:byte(i)-m2:byte(i)+c
	  res.mant=c%10 .. res.mant
	  c=math.floor(c/10)
	end
	return correct(res)
  end,
  __mul=function(op1,op2)
    if getmetatable(op1)~=m_table then op1=metanum(op1) end
    if getmetatable(op2)~=m_table then op2=metanum(op2) end
	local m1,m2=#op1.mant,#op2.mant
	if m2>m1 then op1,op2 = op2,op1 m1,m2=m2,m1 end
	local res=metanum()
	local c=0
	for i=1,m2-1 do
	  for j=1,i do
	    c=(op1.mant:byte(j-i-1) - 48)*(op2.mant:byte(-j) - 48)+c
	  end
	  res.mant=c%10 .. res.mant
	  c=math.floor(c/10)
	end
	for i=m2,m1 do
	  for j=1,m2 do
	    c=(op1.mant:byte(j-i-1) - 48)*(op2.mant:byte(-j) - 48)+c
	  end
	  res.mant=c%10 .. res.mant
	  c=math.floor(c/10)
	end
	for i=m1+1,m1+m2-1 do
	  for j=i-m1+1,m2 do
	    c=(op1.mant:byte(j-i-1) - 48)*(op2.mant:byte(-j) - 48)+c
	  end
	  res.mant=c%10 .. res.mant
	  c=math.floor(c/10)
	end
	res.mant= c .. res.mant
	res.neg= op1.neg~=op2.neg
	res.exp=op1.exp+op2.exp
	return correct(res)
  end,
  __div=function(op1, op2)
	return division(op1,op2,getmetatable(op1)==m_table and rawget(op1,"divprec"))
  end,
  __mod=function(op1, op2)
    local res=division(op1,op2,0)
	return op1-res*op2
  end,
  __pow=function(op1,op2)
    op2=math.floor(op2)
    if op2<0 then return metanum() end
    if op2==0 then return metanum("1") end
    if op2==1 then return metanum(op1) end
	local res=op1^(op2/2)
	if op2%2==0 then return res*res end
	return res*res*op1
  end,
  __eq=function(op1,op2)
	if op1.neg ~= op2.neg  then return false end
	if op1.mant~= op2.mant then return false end
	if op1.exp ~= op2.exp  then return false end
	return true
  end,
  __lt=function(op1,op2)
	if op1.neg ~= op2.neg then return op1.neg end
	local m1,m2=getMant(op1,op2)
	for i=1,#m1 do
	  if m1:byte(i)<m2:byte(i) then return not op1.neg end
	  if m1:byte(i)>m2:byte(i) then return op1.neg end
	end
	return false
  end,
  __le=function(op1,op2)
	if op1.neg ~= op2.neg then return op1.neg end
	local m1,m2=getMant(op1,op2)
	for i=1,#m1 do
	  if m1:byte(i)<m2:byte(i) then return not op1.neg end
	  if m1:byte(i)>m2:byte(i) then return op1.neg end
	end
	return true
  end,
  __concat=function(op1, op2)
    return tostring(op1)..tostring(op2)
  end
}

function metanum(num,divprec)
  if type(num)=="number" then
    num=tostring(num)
	local m,n=num:match("(.+)e(.+)")
	if n then
	  num=metanum(m,divprec)
	  num.exp=num.exp+n
	  return num
	end
    return metanum(num,divprec)
  end
  local obj={neg=false, mant="", exp=0, divprec=divprec}
  if getmetatable(num)==m_table then
	obj.neg=num.neg obj.mant=num.mant obj.exp=num.exp
  elseif type(num)=="string" then
    local s=num:sub(1,1)
    if s=="-" or s=="+" then num=num:sub(2) obj.neg=(s=="-") end
	s,num=num:sub(1,1),num:sub(2)
    while s>="0" and s<="9" do
	  obj.mant=obj.mant..s
	  s,num=num:sub(1,1),num:sub(2)
	end
	if s=="." then
	  s,num=num:sub(1,1),num:sub(2)
      while s>="0" and s<="9" do
	    obj.mant=obj.mant..s
	    obj.exp=obj.exp-1
	    s,num=num:sub(1,1),num:sub(2)
	  end
	end
  end
  setmetatable(obj,m_table)
  return correct(obj)
end

return metanum
