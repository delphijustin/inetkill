library inetkill;
(*

*)
uses
  System.SysUtils,
  idhashcrc,
  winapi.CommDlg,
  Winapi.Windows,
  winapi.ShellAPI,
  winapi.IpHlpApi,
  winapi.IpTypes,
  System.Classes;
{$RESOURCE iksw.res}
{$R *.res}
Const appname='delphijustin Internet Kill Switch';//program name
appAuthor='Justin Roeder';//change this to your full name
appkey_path='Software\Justin\InternetKillSwitch';//the app registry key
appver=1.0;
reg_gwquery='GWQuery';
reg_lastgw='LastGateway';
reg_classes='Classes';
reg_process='ProcessIDs';
reg_noforcegateway='NoForceGateway';
err_gw_not_found='No gateway IPs begin with "%s" were found';
route_exe='%s\route.exe';
reg_memory='Memory';
runprogram_cmd='%s\rundll32.exe %s,runProgram ';
type TIPv4=array[0..15]of char;
TKiller=record
  Active:boolean;
  GWQuery:TIPv4;
end;
var Gateways:TStringlist;
ret:DWord=0;
route_exec:shellexecuteinfo;
dllname:array[0..max_path]of char;
appkey,memkey,pidk:hkey;
sysdir:array[0..max_path]of char;
lasterror:array[byte]of char;
created:Boolean=false;
function iksw_Error(lpbuffer:PChar;len:integer):integer;stdcall;
begin
if lpbuffer=nil then
lasterror[0]:=#0;
result:=strlen(lasterror);
if lpbuffer<>nil then
strlcopy(lpbuffer,lasterror,len);
end;
  function GetLocalAddressesByAdaptersInfo:boolean;
  var
    Ret: DWORD;
    BufLen: ULONG;
    Adapter, Adapters: PIP_ADAPTER_INFO;
    IPAddr, Gateway: PIP_ADDR_STRING;
  begin
    BufLen := 1024*15;
    result:=true;
    GetMem(Adapters, BufLen);
    try
      repeat
        Ret := GetAdaptersInfo(Adapters, BufLen);
        case Ret of
          ERROR_SUCCESS:
          begin
            // Windows CE versions earlier than 4.1 may return ERROR_SUCCESS and
            // BufLen=0 if no adapter info is available, instead of returning
            // ERROR_NO_DATA as documented...
            if BufLen = 0 then begin
              Exit;
            end;
            Break;
          end;
          ERROR_NOT_SUPPORTED,
          ERROR_NO_DATA:
            Exit;
          ERROR_BUFFER_OVERFLOW:
            ReallocMem(Adapters, BufLen);
        else
          begin result:=false;strlfmt(lasterror,255,'NetAdapt:%s(0x%x)',[
          syserrormessage(ret),ret]);
          exit;
          end;
        end;
      until False;

      if Ret = ERROR_SUCCESS then
      begin
        Adapter := Adapters;
        repeat
          IPAddr := @(Adapter^.IpAddressList);
          repeat
            // use IPAddr^.IpAddress.S as needed...
            IPAddr := IPAddr^.Next;
          until IPAddr = nil;
          Gateway := @(Adapter^.GatewayList);
          repeat
            // use Gateway^.IpAddress.S as needed...
            gateways.Append(Gateway.IpAddress.S);
            Gateway := Gateway^.Next;
          until Gateway = nil;
          Adapter := Adapter^.Next;
        until Adapter = nil;
      end;
    finally
          FreeMem(Adapters);
    end;
  end;


function iksw_Startup:Single;stdcall;
begin
result:=appver;
getmodulefilename(hinstance,dllname,max_path+1);
  zeromemory(@route_exec,sizeof(route_exec));
  getsystemdirectory(sysdir,max_path+1);
  route_exec.cbSize:=sizeof(route_exec);
route_exec.lpParameters:=stralloc(256);
iksw_error(nil,0);
if error_success<>regcreatekeyex(hkey_local_machine,appkey_path,0,nil,
reg_option_non_volatile,key_all_access,nil,appkey,nil)then begin result:=-appver;
strcopy(lasterror,'Failed to open/create registry keys');
end;
if result=appver then regcreatekeyex(appkey,reg_memory,0,nil,reg_option_volatile,
key_all_access,nil,memkey,nil);
regcreatekeyex(memkey,reg_process,0,nil,reg_option_volatile,key_all_access,nil,
pidk,nil);
gateways:=tstringlist.Create;
if not GetLocalAddressesByAdaptersInfo then result:=-appver;
created:=true;
end;
procedure iksw_cleanup;
begin
created:=false;
  gateways.Free;
  strdispose(route_exec.lpParameters);
  regclosekey(pidk);
  regclosekey(memkey);
  regclosekey(appkey);
end;
function findGateWay(const query:String):integer;
var
  I: Integer;
begin
  result:=-1;
  for I := 0 to gateways.Count-1 do
  if pos(query,gateways[i])=1then result:=i;
end;
procedure restoreGatewayW(hw:hwnd;inst:hinst;lpparam:pchar;nshow:integer);stdcall;
var gw:TIPv4;
rs,exitc:dword;
begin
if not created then if iksw_startup<>appver then begin if nshow<>sw_hide then messagebox(0,lasterror,appname,mb_iconerror);iksw_cleanup;exit;end;
rs:=sizeof(gw);
if strlen(lpparam)=0then begin
if regqueryvalueex(appkey,reg_lastgw,nil,nil,@gw,@rS)<>error_success then
begin
strcopy(lasterror,'Failed to get last gateway IP');
//if nshow<>SW_HIDE then
//  messagebox(hw,lasterror,appname,mb_iconerror);
end;
end else begin
if findgateway(lpparam)=-1 then
begin
strlfmt(lasterror,255,err_gw_not_found,[lpparam]);
//if nshow<>SW_HIDE then messagebox(hw,lasterror,appname,mb_iconerror);
if not created then
end;
strpcopy(gw,gateways[findgateway(lpparam)]);
end;
  route_exec.fMask:=SEE_MASK_NOCLOSEPROCESS or SEE_MASK_DOENVSUBST;
  route_exec.lpFile:=strfmt(Stralloc(max_path+1),route_exe,[sysdir]);
  strlfmt(route_exec.lpParameters,255,
  '-p add 0.0.0.0 mask 0.0.0.0 %s',[gw]);
  if not shellexecuteex(@route_exec)then begin
   strplcopy(lasterror,syserrormessage(getlasterror),255);
  end;
  waitforsingleobject(route_exec.hProcess,5*60000);
  getexitcodeprocess(route_exec.hProcess,exitc);
  if exitc=still_active then terminateprocess(route_exec.hProcess,2);
  closehandle(route_exec.hProcess);
end;
procedure displayGatewaysW(hw:hwnd;inst:hinst;query:PChar;nShow:integer);stdcall;
begin
  if iksw_startup<>appver then begin if nshow<>sw_hide then messagebox(0,lasterror,appname,mb_iconerror);iksw_cleanup;exit;end;
  if findgateway(query)=-1then
  messagebox(hw,PChar(gateways.Text),appname,0)else
  messagebox(hw,pchar(gateways[findgateway(query)]),appname,0);

end;
procedure killGatewayW(hw:hwnd;inst:hinst;gateway:pchar;nshow:integer);stdcall;
var gw,lastgw:TIPv4;
rs,exitc:dword;
begin
if not created then if iksw_startup<>appver then begin if nshow<>sw_hide then messagebox(0,lasterror,appname,mb_iconerror);iksw_cleanup;exit;end;
rs:=sizeof(gw);
if strlen(gateway)=0then regqueryvalueex(appkey,reg_gwquery,nil,nil,@gw,@rS)
else strlcopy(gw,gateway,15);
if findgateway(gw)=-1 then
begin
strlfmt(lasterror,255,ERR_GW_NOT_FOUND,[gw]);
// if nshow<>sw_hide then messagebox(hw,lasterror, appname,mb_iconerror);
   iksw_cleanup;exit;
end;
strpcopy(lastgw,gateways[findgateway(gw)]);
  route_exec.fMask:=SEE_MASK_NOCLOSEPROCESS or SEE_MASK_DOENVSUBST;
  route_exec.lpFile:=strfmt(stralloc(max_path+1),route_exe,[sysdir]);
  strlfmt(route_exec.lpParameters,255,'-p delete 0.0.0.0 %s',[lastgw]);
  if not shellexecuteex(@route_exec)then iksw_cleanup;exit;
  waitforsingleobject(route_exec.hProcess,5*60000);
  getexitcodeprocess(route_exec.hProcess,exitc);
  if exitc=still_active then begin terminateprocess(route_exec.hProcess,2);
  closehandle(route_exec.hProcess);iksw_cleanup;exit;end;
  if exitc=0then
  if error_success<>regsetvalueex(appkey,reg_lastgw,0,reg_sz,
  @lastgw,(1+strlen(lastgw))*sizeof(char))then
  iksw_cleanup;
end;

function iksw_isAppRunning(options:integer):bool;stdcall;
var I:integer;
pidcount,vn:DWord;
h:thandle;
processid:Array[0..32]of char;
begin
pidcount:=0;
result:=false;
regqueryinfokey(pidk,nil,nil,nil,nil, nil, nil, @pidcount,nil, nil, nil,nil);
for i:=0to pidcount-1 do
begin
vn:=33;
regenumvalue(pidk,i,processid,vn,nil,nil,nil,nil);
if comparestr(uinttostr(getcurrentprocessid),processid)<>0then
begin
h:=openprocess(PROCESS_QUERY_INFORMATION,false,strtouintdef(processid,0));
result:=(h>0)or result;
if h>0then closehandle(h);
end;
end;
end;

function killGatewayThread(var Info:TKiller):DWORD;stdcall;
var gw:TIPv4;
pid:array[0..32]of char;
rs:dword;
begin
if not created then
iksw_startup;
  result:=0;
  regsetvalueex(pidk,strfmt(pid,'%u',[getcurrentprocessid]),0,reg_sz,
  getcommandline,(1+strlen(getcommandline))*Sizeof(char));
  while info.Active do
  begin
  gateways.clear;
  GetLocalAddressesByAdaptersInfo;rs:=sizeof(gw);gw[0]:=#0;
  regqueryvalueex(appkey,reg_gwquery,nil,nil,@gw,@rs);
if (findgateway(gw)>-1)then killgatewayw(0,1,'',sw_hide);
    if not created then iksw_startup;
  end;
  regdeletevalue(pidk,pid);
  restoregatewayw(0,0,'',sw_hide);
end;

procedure runProgramW(hw:hwnd;inst:hinst;command:pchar;nshow:integer);stdcall;
var shellexec:Shellexecuteinfo;
sl:TStringlist;
filedlg:TOpenFilename;
selfile:Array[0..max_path]of char;
pid:array[0..32]of char;
begin
  if not created then if iksw_startup<>appver then begin if nshow<>sw_hide then messagebox(0,lasterror,appname,mb_iconerror);iksw_cleanup;exit;end;
  zeromemory(@shellexec,sizeof(shellexec));
  sl:=tstringlist.Create;
  sl.Delimiter:=#32;
  sl.StrictDelimiter:=true;
  sl.DelimitedText:=command;
  shellexec.cbSize:=sizeof(shellexec);
  shellexec.fMask:=SEE_MASK_NOCLOSEPROCESS or SEE_MASK_DOENVSUBST or
  (SEE_MASK_FLAG_NO_UI*ord(nShow=sw_hide));
  shellexec.Wnd:=hw;
  if sl.Count=0then
  begin
  strcopy(lasterror,'Blank command');
    zeromemory(@filedlg,sizeof(filedlg));
    filedlg.lStructSize:=sizeof(filedlg);
    filedlg.hWndOwner:=hw;
    filedlg.lpstrFile:=strcopy(selfile,'');
    filedlg.nMaxFile:=max_path+1;
    filedlg.lpstrTitle:='Browse...';
    filedlg.Flags:=OFN_DONTADDTORECENT or OFN_ENABLESIZING or OFN_LONGNAMES or
     OFN_HIDEREADONLY or OFN_FILEMUSTEXIST;
    if not getopenfilename(filedlg) then
      begin
      strcopy(lasterror,'No file was choosen');
      sl.Free;
      iksw_cleanup;exit;
      end;
    sl.Append(selfile);
  end;
  shellexec.nShow:=nshow;
  shellexec.lpFile:=strpcopy(stralloc(1+length(sl[0])),sl[0]);
  sl.Delete(0);
  if sl.Count>0 then
  shellexec.lpParameters:=strpcopy(stralloc(1+length(sl.DelimitedText)),
  sl.DelimitedText);sl.free;
  if not iksw_isapprunning(0)then
  killgatewayw(hw,0,'',nshow);
  regsetvalueex(pidk,strfmt(pid,'%u',[getcurrentprocessid]),0,reg_sz,
  getcommandline,(1+strlen(getcommandline))*sizeof(char));
  sleep(5000);
  if shellexecuteex(@shellexec)then begin
    waitforsingleobject(shellexec.hProcess,infinite);
    closehandle(shellexec.hProcess);
  end; regdeletevalue(pidk,pid);
  if not iksw_isapprunning(0)then
  restoregatewayw(hw,0,'',nshow);
  strdispose(shellexec.lpParameters);
end;
procedure registerGatewayW(hw:hwnd;inst:hinst;query:pchar;nshow:integer);stdcall;
begin
  if not created then
  if iksw_startup<>appver then begin if nshow<>sw_hide then messagebox(0,lasterror,appname,mb_iconerror);iksw_cleanup;exit;end;
  if findgateway(query)=-1then begin
  strlfmt(lasterror,255,err_gw_not_found,[query]);
  if nshow<>sw_hide then messagebox(hw,lasterror,appname,mb_iconerror);
    iksw_cleanup;exit;
  end;
 if nshow<>sw_hide then messagebox(hw,pchar(syserrormessage(regsetvalueex(appkey,reg_gwquery,0,reg_sz,
  query,(1+strlen(query))*sizeof(char)))),appname,mb_iconinformation);
end;
procedure helpW(hw:hwnd;inst:hinst;reserved:pchar;nshow:integer);stdcall;
begin
messagebox(hw,pchar(
'Usage: rundll32.exe inetkill.dll,<CommandName> [parameters]'#13#10+
'Command List:'#13#10+
'about                      Displays app version'#13#10+
'displayGateways [ipQuery]  Displays gateway IPs that begin with [ipquery] or all gateways if left out'#13#10+
'registerGateway [ipQuery]  Registers the [ipQuery] so that you don'#39't need to remember it'#13#10+
'killGateway [ipQuery]      Enables Internet Kill Switch'#13#10+
'restoreGateway [ipQuery]   Disable Internet Kill Switch'#13#10+
'runProgram [program]       Enables Internet Kill Switch until [program] closes'#13#10+
'toggleGateway [ipQuery]    Toggle the Internet Kill Switch'#13#10+
'start [ipQuery]            Easy way to enable the Internet Kill Switch'#13#10+
'registerURL [protocol]     Registers/Unregisters a URL Handler'#13#10+
'registerFileType [fileType] Registers/Unregisters a URL Handler'
),appname,0);
end;
procedure aboutW(hw:hwnd;inst:hinst;reserved:pchar;nshow:integer);stdcall;
var text:array[byte]of char;
crc:tidhashcrc32;
fs:tfilestream;
begin
if not created  then
iksw_startup;
fs:=tfilestream.Create(createfile(dllname,generic_read,file_share_read or
file_share_write or file_share_delete,nil,open_existing,file_attribute_normal,0));
crc:=tidhashcrc32.Create;
messagebox(hw,strlfmt(text,255,
'%s v%n By %s'#13#10'App CRC32:%.8x'#13#10'Special Thanks goes to stackoverflow.com for the networking api exampled used in this app.',[appname,
appver*1.0,appauthor,crc.HashValue(fs)]),'About',0);
crc.free;
fs.free;
end;
procedure toggleGatewayW(hw:hwnd;inst:hinst;lpQuery:pchar;nshow:integer);stdcall;
var gwquery:TIPv4;
rs:dword;
begin
  if not created then iksw_startup;
  rs:=sizeof(gwquery);
  regqueryvalueex(appkey,reg_gwquery,nil,nil,@gwquery,@rs);
  if strlen(lpquery)>0then strlcopy(gwquery,lpquery,15);
  if findgateway(gwquery)=-1then restoregatewayw(hw,0,'',nshow)else
  killgatewayw(hw,0,'',nshow);
end;
procedure registerURLW(hw:hwnd;inst:hinst;protocol:pchar;nshow:integer);stdcall;
var hkurl,hkclass:hkey;
rs,rtype:dword;
oldCmdLine,newcmdline:Array[0..1024]of char;
urlpath:array[byte]of char;
begin
if not created then iksw_startup;
if regopenkeyex(hkey_classes_root,strlfmt(urlpath,255,'%s\shell\open\command',[
  protocol]),0,key_all_access,hkurl)<>error_success then begin
    strcopy(lasterror,'Class key could not open');
    if nshow<>sw_hide then messagebox(hw,lasterror,appname,mb_iconerror);
    iksw_cleanup;exit;
  end;
  rs:=sizeof(oldcmdline);
  strcopy(oldcmdline,':ERROR:');
  regqueryvalueex(hkurl,nil,nil,@rtype,@oldcmdline,@rS);
  regcreatekeyex(appkey,reg_classes,0,nil,reg_option_non_volatile,key_all_access,
  nil,hkclass,nil);
if pos(lowercase(dllname),lowercase(oldcmdline))=0 then begin
  regsetvalueex(hkclass,protocol,0,rtype,@oldcmdline,rs);
  Strlcat(strfmt(newcmdline,runprogram_cmd,[sysdir,dllname]),oldcmdline,1024);
  regsetvalueex(hkurl,nil,0,rtype,@newcmdline,(1+strlen(newcmdline))*sizeof(char));
end else begin
rs:=sizeoF(newcmdline);
  regqueryvalueex(hkclass,protocol,nil,@rtype,@newcmdline,@rs);
  regsetvalueex(hkurl,nil,0,rtype,@newcmdline,(1+strlen(newcmdline))*Sizeof(char));
end;
regclosekey(hkurl);
regclosekey(hkclass);
    if comparestr(':ERROR:',oldcmdline)=0then
    begin
    strcopy(lasterror,'Failed to read file class data from registry.');
      if nshow<>sw_hide then
      messagebox(hw,lasterror,appname,mb_iconerror);
      regclosekey(hkurl);
      iksw_cleanup;exit;
    end;
strdispose(oldcmdline);
if created then iksw_cleanup;
end;
procedure registerFileTypeW(hw:hwnd;inst:hinst;fileext:pchar;nshow:integer);stdcall;
var fileclass:hkey;
classname:array[byte]of char;
rs:DWORD;
begin
if fileext[0]<>'.'then begin
  strcopy(lasterror,'Parameter needs to begin with a period');
  if nshow<>SW_HIDE then
  messagebox(hw,lasterror,appname,mb_iconerror);
  exit;
end;
if regopenkeyex(hkey_classes_root,fileext,0,key_read,fileclass)<>error_success
then begin
  strcopy(lasterror,'Failed to read file extension');
  if nshow<>SW_HIDE then
  messagebox(hw,lasterror,appname,mb_iconerror);
  exit;
end;
rS:=sizeof(classname);
classname[0]:=#0;
regqueryvalueex(fileclass,nil,nil,nil,@classname,@rs);
regclosekey(fileclass);
if strlen(classname)=0then exit;
registerurlw(hw,inst,classname,nshow);
end;

procedure errorLevelW(hw:HWND;inst:Hinst;lpType:pchar;nShow:integer);stdcall;
var ret:DWord;
begin
ret:=0;
iksw_startup;
case strtouintdef(lptype,maxdword)of
0:ret:=ord(iksw_isapprunning(0));
end;
iksw_cleanup;
exitprocess(ret);
end;

procedure startW(hw:HWND;inst:Hinst;lpQuery:pchar;nShow:integer);stdcall;
var msgbox:MSGBOXPARAMS;
killer:THandle;
kdata:TKiller;
TID:DWord;
pid:array[0..32]of char;
begin
strpcopy(pid,uinttostr(getcurrentprocessid));
regsetvalueex(pidk,pid,0,reg_sz,getcommandline,(1+strlen(getcommandline))*Sizeof(
char));
if not created then iksw_startup;
kdata.Active:=true;
strlcopy(kdata.GWQuery,lpquery,15);
killer:=createthread(nil,0,@killgatewaythread,@kdata,0,tid);
zeromemory(@msgbox,sizeof(msgbox));
msgbox.cbSize:=sizeof(msgbox);
msgbox.hInstance:=hinstance;
msgbox.lpszText:='Click OK when it is ok to disable the Internet Kill Switch';
msgbox.lpszCaption:=appname;
msgbox.dwStyle:=mb_usericon;
msgbox.lpszIcon:=makeintresource(1);
messageboxindirect(msgbox);
kdata.Active:=false;
waitforsingleobject(killer,infinite);closehandle(killer);
iksw_cleanup;exitprocess(idcancel);
end;
procedure NULLGatewayW(hw:hwnd;inst:hinst;reserved:pchar;nshow:integer);stdcall;
begin
(*
 This function is for the NULL option on torrents.cmd batch file
*)
end;
exports displayGatewaysW,killGatewayW,restoreGatewayW,runProgramW,helpW,aboutW,
registerGatewayW,iksw_Error,toggleGatewayW,registerURLW,registerFileTypeW,startW,
errorLevelW,NULLGatewayW;
begin
end.
