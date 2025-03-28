        ��  ��                  ��  0   L U A S C R I P T   ��e     0 	        
{$lua}
[ENABLE]
registerSymbol('proc',getAddress(process))
[DISABLE]
unregisterSymbol('proc')
lua_plugin_print("proc remove")

MyLuaScriptName:注册通用进程符号
[ENABLE]

{$lua}
local function getModuleStringList()
    local string_list = createStringList();
    module_list = enumModules(getOpenedProcessID());
    print(#module_list)
    for i=1,#module_list do
        local m = module_list[i];
        printf("%s--%X--%s,%s",m.Name,m.Address,m.Is64Bit,m.PathToFile);
        string_list.add(m.Name);
    end
    return string_list;
end
local select_index,my_module_name = showSelectionList("模块列表","选择要导入符号的模块",getModuleStringList(),false)
if select_index < 0 then
  my_module_name = process;
end
function readFile(filePath,method)--创建读取文件函数
    if method==nil then
       method = "r+"
    end
    local file = io.open(filePath,method)
    if file == nil then
        print("file1 open failed-文件打开失败")
    end
    assert(file,"file1 open failed-文件打开失败")--如果文件不存在，则提示：文件打开失败

    local fileTab = {}--创建一个局部变量表
    local line = file:read()--读取文件中的单行内容存为另一个变量
    while line do--当读取一行内容为真时
        table.insert(fileTab,line)--在fileTab表末尾插入读取line内容
        line = file:read()--读取下一行内容
    end
    file:close()
    return fileTab --内容读取完毕，返回表
end
function StringToHex(str)

   str = string.gsub(str," ","");
   Strlen = string.len(str);
   Hex = 0x0
   for i = 1, Strlen do
       temp = string.byte(str,i)

       if ((temp >= 48) and (temp <= 57)) then
           temp = temp - 48
       elseif ((temp >= 97) and (temp <= 102)) then
           temp = temp - 87
       elseif ((temp >= 65) and (temp <= 70)) then
           temp = temp - 55
       else
           return "isNotHex"
       end
       Hex =  Hex + temp*(16^(Strlen-i))
   end
   if Strlen==0 then
       return "isNotHex"
   end
   return (Hex)
end
function strSplit(str,regex)
   local strTab = {};
   regex =string.format('([^%s]+)',regex);
   local i=1;
   for word in string.gmatch(str, regex) do
       strTab[i]=word;
       i = i+1;
   end
   return strTab;
end

function dissectPEHeader(module)
  local base = getAddress(module)
  local msdosSize = byteTableToDword(readBytes(base + 0x3C, 2, true))
  local headerBase = base + msdosSize
  local numOfSections = byteTableToDword(readBytes(headerBase + 6, 2, true))
  local optionalHeaderSize = byteTableToDword(readBytes(headerBase + 20, 2, true))
  local sectionArrayBase = headerBase + 24 + optionalHeaderSize

  local pe_header = {
    base = base;
    msdosSize = msdosSize;
    headerBase = headerBase;
    numOfSections = numOfSections;
    optionalHeaderSize = optionalHeaderSize;
    sectionArrayBase = sectionArrayBase;
  };

  for i = 0, numOfSections - 1 do
    local sectionBase = sectionArrayBase + i * 40
    local sectionName = readString(sectionBase, 8)
    pe_header[sectionName] = {
      name = sectionName;
      base = sectionBase;
      size = byteTableToDword(readBytes(sectionBase + 8, 4, true));
      address = byteTableToDword(readBytes(sectionBase + 12, 4, true));
      sizeOfRawData = byteTableToDword(readBytes(sectionBase + 16, 4, true));
      pointerToRawData = byteTableToDword(readBytes(sectionBase + 20, 4, true));
      pointerToRawRelocations = byteTableToDword(readBytes(sectionBase + 24, 4, true));
      pointerToLineNumbers = byteTableToDword(readBytes(sectionBase + 28, 4, true));
      numOfRelocations = byteTableToDword(readBytes(sectionBase + 32, 2, true));
      numOfLineNumbers = byteTableToDword(readBytes(sectionBase + 34, 2, true));
      characteristics = byteTableToDword(readBytes(sectionBase + 36, 4, true));
    };
    -- 同时按区段号记录一下Header
    pe_header[i] = pe_header[sectionName];
  end

  return pe_header;
end
header = dissectPEHeader("unityplayer.dll") -- Enter your module here!
moduleBase = header.base -- moduleBase now contains the base address of the module
numberOfSections = header.numOfSections -- Number of sections in your module
print(string.format("moduleBase:0x%x", moduleBase))
print(string.format("numberOfSections:%d", numberOfSections))
for i=0,numberOfSections-1 do
    local name = header[i].name;
    local addr = header[i].address;
    local size = header[i].size;
    print(string.format("(%d) -- %s -- 0x%x -- 0x%x",i, name,addr,size))
end



load_dialog = createOpenDialog(self)
load_dialog.InitalDir = os.getenv('%USERPROFILE%')
load_dialog.Filter = 'Executable files|*.map;*.BAT;*.CMD;*.sh|Bat files (*.bat)|*.BAT|Exe files (*.exe)|*.EXE|All files (*.*)|*'
load_dialog.execute()
print(load_dialog.FileName)   --- shoud be change to shell execute to run app

local file = load_dialog.FileName
local lines = readFile(file)

sl = createSymbolList()

valueList = {}
-- Iterate through the lines in the map file
for k,line in pairs(lines) do
  local pre_location = 0x0;
  -- Capture the section, offset, and symbol name
  if  string.find(line,':')~=nil then
       local v = strSplit(line,":");

       local good_values =  strSplit(v[2]," ");
       --print(line);
       
       if #good_values == 2 then
        
         local name = good_values[2];
         if string.match(name, "^loc") and string.find(name,'_')~=nil then
          --pass
         else
          local section_num = StringToHex(v[1])-1;
          local location =StringToHex(good_values[1])+header[section_num].address;
          table.insert(valueList,{name=name,location=location});
         end
    
       end

  end
end

for k,value in pairs(valueList) do
     local name =value.name;
     local location = getAddress(my_module_name)+value.location; --tonumber("0x" .. location)
     local size = 20;
     if k < #valueList then
             size = valueList[k+1].location-value.location;--tonumber("0x" .. size)
     end
    
     sl.addSymbol(my_module_name, name, location, size)
     --print(string.format("%s %x %x",name,location,size))
     
end

sl.register()


{$asm}

[DISABLE]

{$lua}

sl.unregister()
sl = nil

{$asm}


MyLuaScriptName:加载IDA-Map调试符号



{$lua}
[ENABLE]
function readFile(filePath,method)--创建读取文件函数
    if method==nil then
       method = "r+"
    end
    local file = io.open(filePath,method)
    assert(file,"file1 open failed-文件打开失败")--如果文件不存在，则提示：文件打开失败
    local fileTab = {}--创建一个局部变量表
    local line = file:read()--读取文件中的单行内容存为另一个变量
    while line do--当读取一行内容为真时
        table.insert(fileTab,line)--在fileTab表末尾插入读取line内容
        line = file:read()--读取下一行内容
    end
    file:close()
    return fileTab --内容读取完毕，返回表
end
function writeFile(filePath,fileTab,method)--创建写入文件函数（文件参数，表参数）
    if method==nil then
       method = "r+"
    end
    local file = io.open(filePath,method)
    assert(file,"file1 open failed")--如果文件不存在，则提示：文件打开失败
    for  i,line in ipairs(fileTab) do--遍历表中的所有记录
        file:write(line)--把遍历的内容逐行写入文件中
        file:write("\n")--逐行内容换行打回车
    end
    file:close()
end
function getOpcodeString(addr)
  local st = disassemble(addr);
  local address,opcode,bytes,extraField = splitDisassembledString(st);
  return opcode;
end

switch = true;
preOpcodeAddr = nil;
max_trace = 0;
function debugger_onBreakpoint()
   if preOpcodeAddr ==nil then
      preOpcodeAddr = RIP
   end
   local nowCode =getOpcodeString(RIP);
   local size=getInstructionSize(preOpcodeAddr)
   if preOpcodeAddr+size ~= RIP then
      print(string.format("from:[0x%X] &lt;%s&gt; to:[0x%X]",preOpcodeAddr,preCode,RIP))
   end
       
    if string.find(nowCode,"ret")==nil and switch and max_trace <100 then
       debug_continueFromBreakpoint(co_stepover)
       max_trace = max_trace+1;
       preOpcodeAddr=RIP;
       return 1
    else
       print(string.format("找到了(清零)：%X 当前RIP:%X",preOpcodeAddr,RIP))
     
       --preOpcodeAddr = nil;
       --debug_continueFromBreakpoint(co_run)

       return 0
    end


end
function func()
 switch = not switch;
 --print(string.format("swithc changeTo:%s",switch));
end
hkey=createHotkey("func", VK_A);
debug_continueFromBreakpoint(co_stepover);
--generichotkey_onHotkey(hkey,func);
[DISABLE]
 getMemoryViewForm().DisassemblerView.TopAddress = preOpcodeAddr;
hkey.destroy()
function debugger_onBreakpoint()
  return 0
end



MyLuaScriptName:持续Trace当前函数直到ret为止(热键版本)

{$lua}
[ENABLE]

oldParentStruct = nil;
parentEle = nil;
local varTypeToStrTable = {"vtByte","vtWord","vtDword","vtQword","vtSingle","vtDouble","vtString","vtWideString","vtByteArray","vtBinary","vtAll","vtAutoAssembler","vtPointer","vtCustom","vtGrouped"}
local function readFile(filePath,method)--创建读取文件函数
    if method==nil then
       method = "r+"
    end
    local file = io.open(filePath,method)
    assert(file,"file1 open failed-文件打开失败")--如果文件不存在，则提示：文件打开失败
    local fileTab = {}--创建一个局部变量表
    local line = file:read()--读取文件中的单行内容存为另一个变量
    while line do--当读取一行内容为真时
        table.insert(fileTab,line)--在fileTab表末尾插入读取line内容
        line = file:read()--读取下一行内容
    end
    file:close()
    return fileTab --内容读取完毕，返回表
end
local function StringToHex(str)
   Strlen = string.len(str)
   Hex = 0x0
   for i = 1, Strlen do
       temp = string.byte(str,i)
       if ((temp >= 48) and (temp <= 57)) then
           temp = temp - 48
       elseif ((temp >= 97) and (temp <= 102)) then
           temp = temp - 87
       elseif ((temp >= 65) and (temp <= 70)) then
           temp = temp - 55
       else
           return "isNotHex"
       end
       Hex =  Hex + temp*(16^(Strlen-i))
   end
   if Strlen==0 then
       return "isNotHex"
   end
   return (Hex)
end
local function strSplit(str,regex)
   local strTab = {};
   regex =string.format('([^%s]+)',regex);
   local i=1;
   for word in string.gmatch(str, regex) do
       strTab[i]=word;
       i = i+1;
   end
   return strTab;
end
local function aobStrToTable(aob)
   local strTab = strSplit(aob,' ');
   local aobTab = {};
   for  i,line in ipairs(strTab) do--Traverse all record in table
        local value = StringToHex(line);
        aobTab[i] = value
   end
   return aobTab;
end

local function P5R_Unlock_All_Persona()

filePath ='D:/1.txt'
valueMap = {}
local fileTab = readFile(filePath)--创建一个局部变量表
for  i,line in ipairs(fileTab) do--遍历表中的所有记录
   local v = strSplit(line,':');
   local byteArray = aobStrToTable(v[1]);
   local description = v[2];
   local str = string.format('size:%d,%s,%s',#byteArray,byteArray,description);
   valueMap[description] = byteArray
   print(str);
end
print(#valueMap['Zouchouten'])

al=getAddressList()
if al.Count>0 then
  for v=0,al.Count-1  do
   local mr = addresslist_getMemoryRecord(al,v);
   if string.find(mr.Description,'基础统计/技能/等级')~=nil and memoryrecord_getAddress(mr)==0x1429ecfcf  then
     for i=0,mr.Count-1 do
      subMr = mr.getChild(i)
      descript = memoryrecord_getDescription(subMr);
      addr =memoryrecord_getAddress(subMr);
      print(string.format('%s->%x->%s',descript,addr,memoryrecord_getValue(subMr)))
      writeBytes(addr,valueMap[descript])
     end
     break;
   end
  end
end

end




local function copyMemoryRecordWithOffsetByTemplateMr(old_mr,new_mr)
    local offset_num = old_mr.getOffsetCount();
    local varType = old_mr.getType();
    new_mr.setDescription(string.format('%s(拷贝)',old_mr.getDescription()));
    new_mr.setAddress(old_mr.getAddress());

    new_mr.setOffsetCount(offset_num);

    if varType == vtString then
        memoryrecord_string_setSize(new_mr,memoryrecord_string_getSize(old_mr));
        memoryrecord_string_setUnicode(new_mr,memoryrecord_string_getUnicode(old_mr));
    end
    new_mr.setType(varType);

    for index=0,offset_num-1 do
        new_mr.setOffset(index,old_mr.getOffset(index));
    end
end

local function showRecord(mr)
    descript = memoryrecord_getDescription(mr);
    addr =memoryrecord_getAddress(mr);
    print(string.format('%s->%x->%s',descript,addr,memoryrecord_getValue(mr)))
end

local function generateMemoryRecordByTemplate(index,offset,name)
    al=getAddressList()
    new_mr = al.createMemoryRecord();
    if al.Count>0 then
        for v=0,al.Count-1  do
            local mr = addresslist_getMemoryRecord(al,v);
            --showRecord(mr);
            if string.find(mr.Description,'由结构体导出制作')~=nil   then
                copyMemoryRecordWithOffsetByTemplateMr(mr,new_mr);
                mr.Options = '[moHideChildren,moAllowManualCollapseAndExpand,moManualExpandCollapse]'
                new_mr.setOffset(index,offset)
                new_mr.setDescription(name);
                new_mr.appendToEntry(mr);
                break;
            end
        end
    end
end

local function calEleValueByStack(stack,nowPk,parent_addr)
    for i=1,#stack do
        local offset = stack[i].element.getOffset();
        parent_addr = readPointer(parent_addr+offset);
    end
    local value_addr = parent_addr+nowPk.element.getOffset();
    local value_type = nowPk.element.getVartype();
    if value_type==vtPointer then
        return readPointer(value_addr);
    elseif value_type==vtByte then
        return readShortInteger(value_addr);
    elseif value_type==vtWord then
        return readSmallInteger(value_addr);
    elseif value_type==vtDword then
        return readInteger(value_addr);
    elseif value_type==vtQword then
        return readQword(value_addr);
    elseif value_type==vtSingle then
        return readFloat(value_addr);
    elseif value_type==vtDouble then
        return readDouble(value_addr);
    else
        return nowPk.element.getValueFromBase(parent_addr);
    end
end
local function createRecordByStack(stack,nowPk,parent_addr)
    local varType = nowPk.element.getVartype();
    new_mr = getAddressList().createMemoryRecord();
    new_mr.setDescription("由结构体导出制作");
    if #stack > 0 then
        new_mr.setAddress(parent_addr+stack[1].element.getOffset());
    else
        new_mr.setAddress(parent_addr+nowPk.element.getOffset());
    end
    if varType==vtUnicodeString then
        memoryrecord_string_setSize(new_mr,20);
        varType = vtString;
        memoryrecord_string_setUnicode(new_mr,true);
    end
    new_mr.setType(varType);
    -- 又由于pointer本身第一次寻址就是指针所以还需要去掉倒数第一个offset，还要-1
    new_mr.setOffsetCount(#stack);
    for index=2,#stack do
        new_mr.setOffset(index-1,stack[#stack-index+2].element.getOffset());
    end
    new_mr.setOffset(0,nowPk.element.getOffset());
    return new_mr;
end

local function addSubEle(parent_ele,default_name,template_element,offset,parent_addr,child_member_name,default_value)
    print(string.format('addSubEle(%s)',parent_ele.getName()));
    local child_struct = parent_ele.getChildStruct();
    local otherType = template_element.getVartype();
    local name = template_element.getName();
    local tmp_child_child_struct = nil;

    if(otherType == vtPointer) then
        tmp_child_child_struct = template_element.getChildStruct();
    end
    local ele = child_struct.addElement();
    ele.setVartype(otherType);
    ele.setOffset(offset);
    ele.setName(name); -- 注意这里需要暂时先重命名为目标元素的名称，否则getMemberValueByEle找不到跟节点的数值

    if tmp_child_child_struct ~=nil then
        ele.setChildStruct(tmp_child_child_struct);
        name = getMemberValueByEle(ele,child_member_name,parent_addr).value;
        print(child_member_name.."name::"..name)
    else

        name = ele.getValueFromBase(parent_addr);
    end
    if default_value ~=nil then
        ele.setValueFromBase(parent_addr,default_value);
    end
    name = string.format('%s_%s(%s)',template_element.getName(),default_name,name);
    ele.setName(name);

    return ele;
end
local function saveOldStruct(parent_ele)
    parentEle = parent_ele;
    oldParentStruct = parentEle.getChildStruct();
    local template_element = oldParentStruct.getElement(0);
    parentEle.setChildStruct(createStructure("MyTemp_"..oldParentStruct.getName()));
    return template_element;
end
function restoreOldStruct()
    if parentEle ~=nil then
       parentEle.setChildStruct(oldParentStruct);
    end
end
local function stackToStr(stack)
    local ret_str = "["
    for i=1,#stack do
        ret_str = ret_str..stack[i].index..","
    end
    ret_str = ret_str.."]";
    return ret_str;
end

local function structAddSubEle(parent_struct,template_element)
    local new_ele = parent_struct.addElement()
    new_ele.name = template_element.name;
    new_ele.offset = template_element.offset;
    new_ele.Vartype = template_element.Vartype;
    new_ele.Bytesize = template_element.Bytesize;
    return new_ele;
end

--结构体树状遍历
function scanManyStructByEle(root_ele,callback,...)
    local stack = {};
    table.insert(stack,{element=root_ele,index=-1});
    while #stack > 0 do
        local nowPk =  stack[#stack];
        local nowIndex = nowPk.index+1;
        local nowElement = nowPk.element;
        nowPk.index = nowIndex;
        local child_struct = nowElement.getChildStruct();
        table.remove(stack); -- 移除第一个元素

        if nowIndex == 0 and callback(root_ele,stack,nowPk,...) then
            return 1;
        end

        if(child_struct) == nil then
            --pass
        elseif (nowIndex<structure_getElementCount(child_struct)) then
            nowElement = child_struct.getElement(nowIndex);
            table.insert(stack,nowPk);
            table.insert(stack,{element=nowElement,index=-1});
        else
            --pass
        end
    end
    return 0;

end

function scanManyStructByRoot(root_struct,callback,...)
   for i=0,structure_getElementCount(root_struct)-1 do
       if scanManyStructByEle(root_struct.getElement(i),callback,...)==1 then
          return 1;
       end
   end
   return 0;
end

function getMemberValueByEle(parent_ele,member_name,parent_addr,generateRecord)
    if generateRecord == nil then
        generateRecord = false;
    end
    local ret_table = {value=nil,stack={},nowPk=nil,generateRecord=generateRecord}
    scanManyStructByEle(parent_ele,get_value_callback,member_name,parent_addr,ret_table);
    return ret_table;
end

-- 内部函数，接收不定长参数
function callback_example(root_ele,stack,nowPk,test,...)
    local args = {...}
    for i, v in ipairs(args) do
      print(i, v)
    end
    return false;
end
function get_value_callback(root_ele,stack,nowPk,member_name,parent_addr,ret_table)
    local nowElement = nowPk.element;
    local ele_name = nowElement.getName();
    if string.find(ele_name,member_name)~=nil then
        print(stackToStr(stack)..ele_name);
        ret_table.value = calEleValueByStack(stack,nowPk,parent_addr);
        ret_table.stack = stack;
        ret_table.nowPk = nowPk;
        if  (ret_table.generateRecord) then

            createRecordByStack(stack,nowPk,parent_addr)
        end
        return true;
    end
    return false;
end
function generate_structure_callback(root_ele,stack,nowPk,member_name,root_addr,child_member_name,...)
    local args = {...}  -- 不定长参数被打包成表
    local start_offset,step_offset,scan_from,scan_to = args[1],args[2],args[3],args[4];
    local nowElement = nowPk.element;
    local ele_name = nowElement.getName();
    print(stackToStr(stack)..ele_name);
    parent_addr = calEleValueByStack(stack,nowPk,root_addr)
    if string.find(ele_name,member_name)~=nil then
        print(string.format('%x',parent_addr));
        getMemberValueByEle(root_ele,child_member_name,root_addr,true);
        local template_element = saveOldStruct(nowElement);
        --选择哪个值作为核心导出信息(最关注的子子子成员的值,举例来说,此处为:物品名称)
        -- getMemberValueByEle(aim_struct.getElement(0),"物品名称",getAddress("SAOFB-Win64-Shipping.exe+4A38EE8"),true);

        local child_stack = getMemberValueByEle(template_element,child_member_name,parent_addr).stack;
        for i=scan_from,scan_to do
            local move_offset = start_offset+step_offset*i;
            local default_value = nil;
            if step_offset==0xA8 then
                --default_value = i + 1;
            end

            local ele = addSubEle(nowElement,string.format('%d',i+1),template_element,move_offset,parent_addr,child_member_name,default_value);
            --又因为mr_offset从0开始索引，stack从1开始索引，所以要再减个1；
            generateMemoryRecordByTemplate(#child_stack,move_offset,ele.getName());

        end
        return true;
    end
    return false;

end

function compare_structure_callback(root_ele,stack,nowPk,addr1,addr2,...)
    local args = {...}  -- 不定长参数被打包成表
    local store_struct,mode = args[1],args[2]
    if mode >=2 then
        for i=1,#stack do
            local rootPk = stack[i];
            if rootPk.store_struct == nil then
                local new_root_ele = structAddSubEle(store_struct,rootPk.element);
                rootPk.store_struct = createStructure(rootPk.element.getChildStruct().getName());
                new_root_ele.setChildStruct(rootPk.store_struct)
                store_struct = rootPk.store_struct;
            else
                store_struct = rootPk.store_struct;
            end
        end
    end
    local nowElement = nowPk.element;
    local ele_name = nowElement.getName();
    print(stackToStr(stack)..ele_name);
    local value1 = calEleValueByStack(stack,nowPk,addr1)
    local value2 = nowElement.name;
    if addr1==addr2 then
        if type(value1) == 'number' then
           value2 = tonumber(nowElement.name);
        end

    else
        value2 = calEleValueByStack(stack,nowPk,addr2);
    end
    local name;
    local equal_mode = 2;--2等于 3*5不等于 3大于 5小于 2*3 大于等于
    if mode < 2 then
        name = string.format("%s",value1);
        nowElement.setName(name);
    elseif value1==value2 then
        name = string.format("%s",value1);
        equal_mode = 2;
    elseif value1 > value2 then
        name = string.format("大于(%s)>(%s)",value1,value2);
        equal_mode = 3;
    else
        name = string.format("小于(%s)<(%s)",value1,value2);
        equal_mode = 5;
    end

    if mode % equal_mode == 0 and nowElement.getChildStruct()==nil then --不是结构指针还满足mode
        local new_ele = structAddSubEle(store_struct,nowElement);
        new_ele.setName("["..varTypeToStrTable[nowElement.getVartype()+1].."]"..name);
    end
    return false;

end





local function getGlobalStructureList()
    local string_list = createStringList();
    local struct_list = {};
    for v=0,getStructureCount()-1 do
        local aim_struct = getStructure(v);
        local struct_name = aim_struct.getName();
        string_list.add(string.format("%s_%d",struct_name,structure_getElementCount(aim_struct)));
        table.insert(struct_list,aim_struct);
    end
   return string_list,struct_list;
end
local function getOptionList(g_option)
    local string_list = createStringList();
    for i=1,#g_option do
        string_list.add( json.encode(g_option[i]) );
    end
    return string_list;
end
local string_list, struct_list = getGlobalStructureList();

if string_list.getCount()>0 then
  local select_index,struct_name = showSelectionList("结构体列表","选择要量产的结构",string_list,false);
  local choice = 0;
  if select_index < 0 then
      choice = messageDialog("是否删除所有结构体","YES = 6为删除, NO = 7为不删除", 2, 0, 1)
      if choice==6 then
         for v=1,#struct_list do
            struct_list[v].removeFromGlobalStructureList()
        end
      end

      choice = 0;
  else
    choice = messageDialog("是否使用比对模式","YES = 6为比对, NO = 7为遍历", 2, 0, 1)
  end
  local aim_struct =struct_list[select_index+1];
  print(struct_name)
  print(aim_struct)
  if choice==6 then --使用比对模式


    local init_tab = {addr1="0x109a8de50",addr2="0x1098f0730",mode=1}


    init_tab = json.decode( lua_plugin_print(json.encode(init_tab),1)) --inputQuery("结构比较初始化", "输入比较参数", )
    local mode = init_tab.mode;
    local pre_str = "";
    local store_struct = nil;
    if mode >= 2 then
        if mode % 5 == 0 then
            pre_str = pre_str.."<"
        end
        if mode % 2 == 0 then
            pre_str = pre_str.."="
        end
        if mode % 3 == 0 then
            pre_str = pre_str..">"
        end
        store_struct = createStructure(pre_str.."_"..struct_name);
        store_struct.addToGlobalStructureList();
    end
    if init_tab ~=nil then
        scanManyStructByRoot(aim_struct,compare_structure_callback,getAddress(init_tab.addr1),getAddress(init_tab.addr2),store_struct,init_tab.mode);
    end
  elseif choice==7 then
    local g_option = {
        {child_name='坐标列表',sub_child_name="X坐标",from="0xDD0*8",step="8",scan_from=0,scan_to=20,root_addr="data_addr7FFA83200DF2"},
        {child_name='物品列表',sub_child_name="受损的壳",from="0x10",step="0xA8",scan_from=0,scan_to=20,root_addr="SAOFB-Win64-Shipping.exe+4C91B58"},
        {child_name='物品列表',sub_child_name="物品名称",from="0x20",step="0x18",scan_from=0,scan_to=20,root_addr="SAOFB-Win64-Shipping.exe+4A38EE8"}
    }
    local index,init_tab = showSelectionList("结构体量产初始化","选择量产参数",getOptionList(g_option),true);
    init_tab = lua_plugin_print(init_tab,1);
    init_tab = json.decode(init_tab)
    if init_tab ~=nil then
        scanManyStructByRoot(aim_struct,generate_structure_callback,init_tab.child_name,getAddress(init_tab.root_addr),init_tab.sub_child_name,getAddress(init_tab.from),getAddress(init_tab.step),init_tab.scan_from,init_tab.scan_to);
    end

  end
end

[DISABLE]

local tmpGroup = getAddressList().getMemoryRecordByDescription("由结构体导出制作");
if tmpGroup ~=nil then
    memoryrecord_delete(tmpGroup);
end
restoreOldStruct();


MyLuaScriptName:结构体量产脚本


{$lua}
[ENABLE]
--save all changed instruction
if commandMap == nil then
commandMap={};
end
function removeAllCreatedMemoryRecords()
al=getAddressList()
tmpDelTable = {}
if al.Count>0 then
    for v=0,al.Count  do
    local mr = addresslist_getMemoryRecord(al,v);
    if mr ~= nil and string.find(mr.Description,'obfuscate ins group')~=nil then
        table.insert(tmpDelTable,mr);
    end
    end
    for  i,mr in ipairs(tmpDelTable) do
    memoryrecord_delete(mr)
    end
end
end
function StringToHex(str)
    Strlen = string.len(str)
    Hex = 0x0
    for i = 1, Strlen do
        temp = string.byte(str,i)
        if ((temp >= 48) and (temp <= 57)) then
            temp = temp - 48
        elseif ((temp >= 97) and (temp <= 102)) then
            temp = temp - 87
        elseif ((temp >= 65) and (temp <= 70)) then
            temp = temp - 55
        else
            return "isNotHex"
        end
        Hex =  Hex + temp*(16^(Strlen-i))
    end
    if Strlen==0 then
        return "isNotHex"
    end
    return (Hex)
end
function strSplit(str,regex)
    local strTab = {};
    regex =string.format('([^%s]+)',regex);
    local i=1;
    for word in string.gmatch(str, regex) do
        strTab[i]=word;
        i = i+1;
    end
    return strTab;
end
function aobStrToTable(aob)
    local strTab = strSplit(aob,' ');
    local aobTab = {};
    for  i,line in ipairs(strTab) do--Traverse all record in table
        local value = StringToHex(line);
        aobTab[i] = value
    end
    return aobTab;
end
function findAndPatch(AOB,RPL)
local ms = createMemScan()
  
local newTable = aobStrToTable(RPL);
ms.firstScan(soExactValue, vtByteArray, nil, AOB, nil, 0x0041001, 0x004fffff,
                            "+X-W-C", nil, nil, true, nil, nil, nil)
ms.waitTillDone()
local fl = createFoundList(ms)
fl.initialize()
local al = getAddressList();
local group = al.createMemoryRecord();
group.Type = vtGrouped;
group.IsGroupHeader = true;
group.Description = table.concat({'obfuscate ins group',string.format('(%d ins)',fl.Count),AOB});
group.Options = '[moHideChildren,moAllowManualCollapseAndExpand,moManualExpandCollapse]';
if fl.Count> 0 then
    for i =0,fl.Count do
    local mr = al.createMemoryRecord()
    mr.Address = fl.Address[i]
    mr.Description = string.format('%dth ins\n',i)
    mr.DontSave = true
    mr.Type = vtByteArray
    mr.CustomTypeName = 'bytes'
    mr.Aob.Size = 8;
    mr.ShowAsHex = true;
    mr.appendToEntry(group);
    local address =StringToHex(fl.Address[i]);
    local originCode = readBytes(address,#newTable,true);
    commandMap[address] = originCode;
    writeBytes(address,newTable)
    end
end
-- free memory allocated by CE for scan/results
fl.destroy()
ms.destroy()
end
  
local AOB = "E8 01 00 00 00 ?? ?? ?? ?? 06 C3"
local RPL = "90 90 90 90 90 90 90 90 90 90 90"
findAndPatch(AOB,RPL);
AOB = "E8 00 00 00 00 81 04 24 17 00 00 00 C3"
RPL = "90 90 90 90 90 90 90 90 90 90 90 90 90"
findAndPatch(AOB,RPL);
  
  
[DISABLE]
if commandMap ~= nil then
for  k,line in pairs(commandMap) do--Traverse all record in table
    writeBytes(k,line);
end
end
removeAllCreatedMemoryRecords();
commandMap = nil;

MyLuaScriptName:去除花指令



{$lua}
[ENABLE]

 
function onOpenProcess(pid)
    symbols.unregister();
    symbols = createSymbolList();
    symbols.register();
 
    reinitializeSymbolhandler();
 
    if (pid == 4) then
        return;
    end
    --getOpenedProcessID();
    local proc = dbk_getPEProcess(pid);
    --printf("proc: %08X", proc);
 
    local peb = readQword(proc + 0x550);
    --printf("peb: %08X", peb);
 
    local ldr = readQword(peb + 0x18);
    --printf("ldr: %08X", ldr);
 
    local index = readQword(ldr + 0x10);
    --printf("index: %08X\n", index);
 
    while (index ~= ldr + 0x10) do
          local mod = readQword(index);
          --printf("mod: %08X", mod);
 
          local name = readString(readQword(mod + 0x58 + 0x8), readSmallInteger(mod + 0x58), true);
          --printf("name: %s", name);
 
          local base = readQword(mod + 0x30);
          --printf("base: %08X", base);
 
          local size = readInteger(mod + 0x40);
          --printf("size: %04X\n", size);
 
          symbols.addModule(name, "", base, size, true);
 
          index = readQword(mod);
    end
 
    local name = readString(proc + 0x5A8, 15);
    --print("name:", name);
 
    local base = readQword(proc + 0x520);
    --printf("base: %08X", base);
 
    local size = readQword(proc + 0x498);
    --printf("size: %04X", size);
 
    symbols.addModule(name, "", base, size);
 
    reinitializeSymbolhandler();
 
    --print("finished!");
end

[DISABLE]
 symbols.unregister();

MyLuaScriptName:修复CE驱动0环调试的模块名称显示

[ENABLE]
 alloc(newmem,2048)
 label(returnhere)
 label(originalcode)
 label(exit)
 
 newmem: //this is allocated memory, you have read,write,execute access
 //place your code here
 
 originalcode:
 mov eax,[esp+8]
 mov [eax],1
 mov eax,1
 ret 8
 
 exit:
 jmp returnhere
 
 USER32.SetWindowDisplayAffinity:
 mov eax,1
 ret 8
 
 USER32.GetWindowDisplayAffinity:
 jmp newmem
 returnhere:
 [DISABLE]
 USER32.SetWindowDisplayAffinity:
 jmp win32u.NtUserSetWindowDisplayAffinity
 
 USER32.GetWindowDisplayAffinity:
 jmp win32u.NtUserGetWindowDisplayAffinity
 
 
 MyLuaScriptName:干掉反录屏
 
{$lua}
[ENABLE]
-- 定义一个Lua表
local myTable = {firstname = "John", lastname = "Doe", age = 23}

-- 将表转换为json字符串
local jsonString = json.encode(myTable)
print(jsonString)

-- 定义一个JSON字符串
local jsonString = '{"firstname":"John","lastname":"Doe","age":23}'

-- 将json字符串解析为Lua表
local myTable = json.decode(jsonString)

-- 访问表属性
print(myTable.firstname) 
print(myTable.lastname)
print(myTable.age)

-- 处理嵌套表
local myTable = {
    name = {first = "John", last = "Doe"},
    age = 23,
    isStudent = true
}

-- 将嵌套表转换为json字符串
local jsonString = json.encode(myTable)
print(jsonString)
[DISABLE]

MyLuaScriptName: dkjson使用案例(将dkjson.lua库放入CE/autorun/xml/文件夹下即可)


[ENABLE]

{$lua}
local record = {}
function debugger_onBreakpoint()
  feature_md5 = string.format("0x%X",RAX)
  if record[feature_md5]==nil then
     record[feature_md5]= 1
  else
     record[feature_md5]=record[feature_md5]+1
  end
  lua_plugin_print(json.encode(record));
  return 0
end



[DISABLE]
{$lua}
function debugger_onBreakpoint()
    return 0
end

MyLuaScriptName: Find Out What Feature Execute Through Breakpoints   