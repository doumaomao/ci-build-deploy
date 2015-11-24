#!/usr/bin/env python2.6

################### check python version ###########################
import sys
if sys.version_info[0] != 2 or sys.version_info[1] < 6:
    print "Error: python version mismatch, please use version 2.x (x >= 6)"
    sys.exit(1)
################## beginning of program ############################
from SocketServer import TCPServer, StreamRequestHandler
from  xml.etree import ElementTree
import os
import shutil
import socket
import hashlib
import json, time
import getopt, subprocess
import logging
import logging.config
import getpass
import stat
import traceback
import copy
import tarfile
import ftplib
import signal

logger=logging.getLogger(__name__)
GIT_REPO=''
GIT_MACHINE=''
VERSION=''
DEF_SERVER=''
SERVER=DEF_SERVER
BACKUP_SERVER=''
current_server=None
PORT=xxxx
login_flag = False   
debug_flag = False
receive_port = xxxx
stamp = ''
outputs=''
env = ''
saved_argv=[]
submitter_dir=''
BASH_FILE_NAME=''
g_file_separator='/'

WORKDIR=''

JOB_BEGIN_TIME=0
CLUSTER_BEGIN_TIME=0
CLUSTER_TRANS_TIME=0
CLUSTER_END_TIME=0
JOB_END_TIME=0

log_file=''
passwd_file = ''

EFATAL = 1
EDISCONN = 2

def summary():
    logger.info('===============Submitter SUM===============')
    logger.info('===============wait_time:%d'%(int(CLUSTER_BEGIN_TIME-JOB_BEGIN_TIME)))
    logger.info('===============cluster_time:%d'%(int(CLUSTER_TRANS_TIME-CLUSTER_BEGIN_TIME)))
    logger.info('===============send_output_time:%d'%(int(CLUSTER_END_TIME-CLUSTER_TRANS_TIME)))
# logger.info('===============release to buildprod.scm time:%d'%(int(JOB_END_TIME-JOB_BEGIN_TIME)))
    logger.info('===============total_time:%d'%(int(JOB_END_TIME-JOB_BEGIN_TIME)))

def manual():
    manual='''build_submitter: to submit a job to compile cluster and get output as finish
version:%s

args:
        -u --url=URL          module's svn url (allow multiple -u) 
                              either beginning with https://, file:// or some local path
        -U --urlfile=URLFILE  modules' svn urls in file, one url per line 
        -c --cmd=CMD          commands for building module, joined with "&&"
                              default: cd "first_url_module" && make -j1
        -C --cmdfile=CMDFILE  commands for building module in file, one command per line
        -B --bashfile=BASHFILE  bash file sent to compile cluster for building modules
        -e --env=ENV          specify compile environment
                              default: GCC3
        -s --server=SERVER    server name or IP addr
                              default: %s
        -p --port=PORT        server port
                              default: 2234
        -o --output=OUTPUT    output from cluster
                              default: output/
        -m --modulepath       releasing module name
           --full-modulepath  releasing full module name
        -h --help             display this help and exit
        -d --workdir          untar to the directory, should be absolute path 
        -t --tag=TAG          specify tag to identify the workspace
        --no-debug            Do not make debug space when compile crashed
        --clean-build         cleaning old workspace, redownload source code before build.
                              Notice: this option will make the job slower.
        --revision-control=git|repo (for git users only) source code management tools.
                              default: repo for http://git.scm.test.com:8088/
        --login               save svn username and password in encrypted format (need prompt)
        --rport=PORT          port to receive build output. contiguous ports will be tried 
                              if the given port is occupied by other service. default: 1234.
        --debug               dump debug message
        -x [USERNAME]
        --use-saved-passwd[=USERNAME]
                              use saved svn account for the build. if this option is 
                              specified without USERNAME, use last login account.
                             
If no args, load command lines from $HOME/.build_submitter/submitter.cache

'''
    print manual%(VERSION,DEF_SERVER)

def sys_quit(quit_code, quit_msg=""):
    print quit_msg
    print '======='
    manual()
    sys.exit(quit_code)
        
def remove_duplicated(urllist):
    result = []
    for a in urllist:
        if a !="" and not result.__contains__(a):
            result.append(a) 
    return result

def read_lines_from_file(filepath):
    '''get url from file'''
    if not os.path.exists(filepath):
        sys_quit(1,'[FATAL] file is not exist,please check it!!!')
    else:    
        pfile=open(filepath,'rb')
        lines=[l.strip() for l in pfile.readlines()]
        pfile.close()
    return lines

def is_WindowsOS():
    if sys.platform == 'win32':
        return True
    return False
    
def get_url_from_file(filepath):
    return remove_duplicated(read_lines_from_file(filepath))

def get_url_by_command(filepath,cmd):
    o = OsCmdStdout(cmd)
    (status,out,err) = o.excute()
    if status:
        logger.error('can not get results by "%s"'%cmd)
        return []
    pathlist=out.split('\n')
    lines=[]
    for p in pathlist:
        dep = "%s/%s" % (filepath,p)
        if p.startswith("../") and os.path.isdir(dep):
            lines.append(dep)
    logger.debug('\n'.join(lines))
    return lines

def get_cmd_from_file(filepath):
    return filter(None,read_lines_from_file(filepath))

def get_product_path_from_file(filepath):
    lines = remove_duplicated(read_lines_from_file(filepath))
    paths = []
    product_flag = "PRODUCT_PATH="
    for line in lines:
        if line.startswith(product_flag):
            paths.append(line[len(product_flag):])
    return paths

def process_x_option(argv):
    argc = len(argv)
    x_option = ''
    x_argument = ''
    for i in range(1, argc):
        arg = argv[i]
        if arg == "-x":
            x_option = "-x"
            x_argument = ''
            argv[i] = ''
            if i < argc - 1 and not argv[i+1].startswith("-"):
                x_argument = argv[i+1]
                argv[i+1] = ''
        elif arg.startswith("--use-saved-passwd"):
            x_option = "--use-saved-passwd"
            x_argument = ''
            if arg.startswith("--use-saved-passwd="):
                x_argument = arg[len("--use-saved-passwd="):]
                argv[i] = ''
            elif arg == "--use-saved-passwd":
                argv[i] = ''
            else:
                x_option = ''
    return x_option, x_argument
    
def parse_cmdline_params():
    argv=sys.argv
    if len(argv) == 1:
        argv=load_cache_cmdline()
    global saved_argv
    saved_argv=copy.deepcopy(argv)

    x_option, x_argument = process_x_option(argv)
    try:
        opts,argvs=getopt.gnu_getopt(argv[1:],"u:U:d:e:c:C:B:s:p:o:m:t:h",
        ["url=",
         "urlfile=",
         "devdiff",
         "workdir=",
         "env=",
         "cmd=",
         "cmdfile=",
         "bashfile=",
         "server=",
         "port=",
         "output=",
         "no-debug",
         "modulepath=",
         "full-modulepath=",
         "rport=",
         "help",
         "debug",
         "login",
         "tag=",
         "build_info=",
         "clean-build",
         "gcc=",
         "revision-control="])
    except getopt.GetoptError:
        sys_quit(1,'[FATAL] GetoptError: Can not parse parameters from cmdline, please check them!!!')
    if x_option:
        opts.append((x_option, x_argument))
    return opts

def getExtracter():
    return HostNameStripper()

class ModulePathExtracter:

    def is_matched(self,orginal):
        pass
    def extract_from(self,orginal):
        pass
    def extract(self, orginal):
        if(self.is_matched(orginal)):
            orginal=self.extract_from(orginal)
        if self.next_extracter!= None:
            return self.next_extracter.extract(orginal)
        return orginal

class HostNameStripper(ModulePathExtracter):
    def __init__(self):
        self.next_extracter= CiStripper()

    def is_matched(self,orginal):
        return orginal.startswith('https://svn.test.com/')
    def extract_from(self,orginal):
        return TrunkExtracter().extract(orginal[len('https://svn.test.com/'):])


class CiStripper(ModulePathExtracter):
    def __init__(self):
        self.next_extracter= IpStripper()

    def is_matched(self,orginal):
        return orginal.startswith('https://svn-ci.test.com/')
    def extract_from(self,orginal):
        return TrunkExtracter().extract(orginal[len('https://svn-ci.test.com/'):])

class IpStripper(ModulePathExtracter):
    def __init__(self):
        self.next_extracter= None

    def is_matched(self,orginal):
        return orginal.startswith('https://scm-svntest.vm.test.com/')
    def extract_from(self,orginal):
        return TrunkExtracter().extract(orginal[len('https://scm-svntest.vm.test.com/'):])
    
class TrunkExtracter(ModulePathExtracter):
    def __init__(self):
        self.next_extracter= BranchExtracter()

    def is_matched(self,orginal):
        return orginal.__contains__('/trunk/')
    def extract_from(self,orginal):
        return orginal.replace('/trunk/','/')
        

class TagExtracter(ModulePathExtracter):
    def __init__(self):
        self.next_extracter= None

    def is_matched(self,orginal):
        return orginal.__contains__('/tags/')

    def extract_from(self,orginal):
        module_path=orginal.replace('/tags/','/')
        if module_path.endswith('/'):
            module_path=module_path[:-1]
        return os.path.dirname(module_path)

class BranchExtracter(ModulePathExtracter):
    def __init__(self):
        self.next_extracter= TagExtracter()

    def is_matched(self,orginal):
        return orginal.__contains__('/branches/')

    def extract_from(self,orginal):
        (product,_,orginal)=orginal.partition('/branches/')
        if orginal=='':
            return ''
        modules=orginal.split('/')
        found=False
        totalnumber=len(modules)
        for i in range(0,totalnumber):
            if modules[totalnumber-i-1].endswith('_BRANCH'):
                modules.__delitem__(totalnumber-i-1)
                found=True
                break
        if found==False:
            return ''
        result='/'.join(modules)
        return '%s/%s'%(product,result)



'''Simplified version of the same func in build_master.py.'''
def extract_module_path(rev):
    return getExtracter().extract(rev.partition('@')[0])

def _isValid(request_message):
    return not request_message['URL']==[]

def load_cache_cmdline():
    cache_file='%s/submitter.cache'%submitter_dir
    if not os.path.exists(cache_file):
        sys_quit(1,'build_submitter: You must specify URL and other info that make the build.')
    logger.debug('Loading command lines from %s'%cache_file)
    try:
        fp=open(cache_file,'r')
        argv=fp.readlines()
        fp.close()
        for i in range(len(argv)):
            argv[i]=argv[i].strip()
        return argv
    except:
        sys_quit(1,'Error when loading command lines from %s'%cache_file)

def cache_cmdline(argv):
    if not argv or len(argv) == 1:
        return
    cache_file='%s/submitter.cache'%submitter_dir
    fp=open(cache_file,'w')
    for v in argv:
        fp.write('%s\n'%v)
    fp.close()
    logger.debug('Cached command lines in %s'%cache_file)

def is_on_hudson():
    #$JOB_NAME and $BUILD_NUMBER etc. are Hudson ENV variables  
    if 'BUILD_NUMBER' in os.environ \
       and 'BUILD_ID' in os.environ \
       and 'JOB_NAME' in os.environ: 
        return True
    return False

def is_on_AGLJENKINS():
    if os.environ.has_key('AGLJENKINS')  \
       and os.environ['AGLJENKINS'] == '1' \
       and is_on_hudson():
        return True
    return False

def init_request(opts):
    global login_flag
    global debug_flag
    global WORKDIR
    request={'URL':[],'ENV':'GCC3','CMD':[],'OUTPUT':'output/','IP':socket.gethostbyname(socket.gethostname())}#jsondata for client 
    has_devdiff=False
    for (k,v)in opts:
        if (k in ('-u','--url')):
            request['URL'].append(v.strip())
        elif (k in ('-U','--urlfile')):
            request['URL'].extend(get_url_from_file(v))
        elif (k == '--devdiff'):
            has_devdiff=True
        elif (k in ('-e','--env')):
            request['ENV']=v
        elif (k in ('-t','--tag')):
            request['TAG']=v
        elif (k in ('-c','--cmd')):
            request['CMD']=v.split('&&')
        elif (k in ('-C','--cmdfile')):
            request['CMD']=get_cmd_from_file(v) 
        elif (k in ('-B','--bashfile')):
            global BASH_FILE_NAME
            BASH_FILE_NAME=v
            request['CMD']=['sh %s'%os.path.basename(v)]
        elif (k in ('-s','--server')):
            global SERVER
            SERVER=v
        elif (k in ('-p','--port')):
            global PORT
            PORT=int(v)
        elif (k in ('-d','--workdir')):
            WORKDIR=v
        elif (k in ('-o','--output')):
            request['OUTPUT']=v
        elif (k in ('--no-debug')):
            request['NO_DEBUG']=True
        elif (k in ('-m','--modulepath')):
            request['MODULEPATH']=v
        elif (k == '--full-modulepath'):
            request['FULL_MODULEPATH']=v
        elif (k == '--login'):
            login_flag = True
        elif (k == '--gcc'):
            request['GCC_VERSION'] = v
        elif (k == '--clean-build'):
            request['CLEAN_BUILD']=True
        elif (k == '--revision-control'):
            request['REVISION_CONTROL'] = v
        elif (k == '--debug'):
            debug_flag = True
        elif (k == '--rport'):
            global receive_port
            receive_port = int(v)
        elif (k in ('-x','--use-saved-passwd')):
            request['USER'] = v
        elif (k == '--build_info'):
            request['OUTPUT_TO_TEST'] = get_product_path_from_file(v)
        elif (k in ('-h','--help')):
            manual()
            sys.exit(0)
  
    if login_flag:
        return None
    if not _isValid(request): 
        sys_quit(1,'[FATAL] Your parameters is invalid, please check it!!!')
    if has_devdiff:
        local_path=request['URL'][0]
        cmd='comake2 --devdiff -C %s'%local_path
        request['URL'].extend(get_url_by_command(local_path,cmd))
    return request

class SvnInfoCommand:
    def __init__(self,workspace=None, url=None):
        self.workspace = workspace
        self.url = url

    def excute(self):
        if is_on_hudson():
            non_interactive = "--non-interactive --trust-server-cert"
        else:
            non_interactive = ""
        if self.workspace:
            command = 'cd %s && svn info --xml %s'%(self.workspace, non_interactive)
        elif self.url:
            command = "svn info %s --xml %s"%(self.url, non_interactive)
        return self._parse(CommandExcuter().excute(command))

    def _parse(self,_output):
        try:    
            doc = ElementTree.fromstring(self._drop_xml_header(_output))
            return doc.find('entry').find('url').text+'@'+doc.find('entry').find('commit').get('revision')
        except:
            logger.error('Can not parse the output of svn info: %s',_output)
            return None
    def _drop_xml_header(self,_output):
        logger.debug(_output[_output.index('?>')+2:])
        return _output[_output.index('?>')+2:]

def format_cmdline_params(opts):
    request=init_request(opts)
    set_log_level()
    global login_flag
    if login_flag == True:
        return request

    for i in range(len(request['URL'])):
        if request['URL'][i].startswith('http://') or request['URL'][i].startswith('https://'):
            continue
        else:
            converted, newurl = convert_local_path(request['URL'][i])
            if converted:
                if is_on_hudson() and i >=1 and newurl.__contains__('@patch'):
                    logger.error('patch was not allowed on hudson invoking build submitter')
                    return None
                request['URL'][i] = newurl
   
    for i in range(0,len(request['CMD'])):
        request['CMD'][i]=normalize_command(request['CMD'][i])
    request['CMD']=filter(None,request['CMD'])

    global BASH_FILE_NAME

    if request['CMD']==[]:
        module_path=extract_module_path(request['URL'][0])
        if module_path == '':
            logger.error ('Fail to guess main module based on the first url')
            return None
        guess_cmd='cd %s'%module_path
        request['CMD']=[guess_cmd,'make -j1','echo this is compile-cluster-generated command']
    elif request['CMD'][0].startswith('sh ') \
        and BASH_FILE_NAME != request['CMD'][0][3:]:
        BASH_FILE_NAME = request['CMD'][0][3:]
        logger.warning('Detected bash file %s. Will send it to compile cluster.'%BASH_FILE_NAME)
    return request

def process_argvs():
    '''check the user imput for building'''
    return format_cmdline_params(parse_cmdline_params())

def normalize_command(cmd):
    while cmd and cmd[-1]==';':
        cmd=cmd[:-1]
    return cmd

def send_jsondata(jsondata, server, port):
    BUFSIZE=1024
    addr=(server, port)
    tcpCliSock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    tcpCliSock.connect(addr)
    tcpCliSock.send(jsondata)
    returndata=tcpCliSock.recv(BUFSIZE)
    tcpCliSock.close()
    return returndata

def translate_listdata_to_json(request):
    return json.dumps(request)

class FileHandler:
    #Open a file. 
    #return filehandler or False.
    def __init__(self,filename,mode):
        self.filename = filename
        self.mode = mode
    def open(self):
        try:
            FH = open(self.filename,self.mode)
        except(IOError), e:
            logger.error("Unable to open file\n", e)
            return False
        else:
            return FH

class OsCmdStdout:    
    def __init__(self,cmd, stdin = None):
        self.cmd=cmd
        self.stdin = stdin
    def excute(self):
        try:    
            p = subprocess.Popen(self.cmd, shell = True , stdin = self.stdin, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
            stdout,stderr = p.communicate()
        except:
            logger.error("Failed to running %s ."%self.cmd) 
        return (p.returncode,stdout,stderr) # string,string


class UntarFile:
    # input tar file flow 
    # return True or False
    def __init__(self, handler):
        self.handler = handler

    def do(self):
        if is_WindowsOS():
            result = self.do_on_Windows()
        else:
            result = self.do_on_Linux()
        return result

    def do_on_Linux(self):
        # 499 don't delete any file automatically, tar overwrite .
        if WORKDIR:
            if not os.path.exists(WORKDIR):
                os.mkdir(WORKDIR)
            tarcmd = "tar -m -x -C %s "%WORKDIR
        else:
            tarcmd = "tar -m -x"
        try:
            sys.stderr.flush()
            sys.stdout.flush()
            p = subprocess.Popen(tarcmd, shell = True , stdin = subprocess.PIPE)
            index = 0
            while True:
                status, data = self.handler.readblock(index)
                if status == 0:
                    p.stdin.write(data)
                    index += 1
                elif status == EFATAL:
                    # fatal error
                    p.stdin.close()
                    p.wait()
                    return EFATAL
                elif status == EDISCONN:
                    break
            p.stdin.close()
            p.wait()
        except:
            traceback.print_exc() 
            return EFATAL

        if p.returncode != 0:
            return EFATAL
        return 0
                
    def do_on_Windows(self):
        # receive tar file
        output_file = 'output_%s_%d_%s.tar' % (getpass.getuser(), os.getpid(), str(time.time()))
        output_fp = open(output_file, "wb")
        
        try:
            sys.stderr.flush()
            sys.stdout.flush()
            index = 0
            while True:
                status, data = self.handler.readblock(index)
                if status == 0:
                    output_fp.write(data)
                    index += 1
                elif status == EFATAL:
                    # fatal error
                    output_fp.close()
                    return EFATAL
                elif status == EDISCONN:
                    break

            output_fp.close()
        except:
            traceback.print_exc() 
            return EFATAL
        
        # untar output
        try:
            if WORKDIR and not os.path.exists(WORKDIR):
                os.mkdir(WORKDIR)
            
            tar_fp = tarfile.open(output_file)
            tar_fp.extractall(WORKDIR)
            tar_fp.close()
        except:
            logger.error("Failed to untar %s" % output_file)
            return EFATAL
        
        if os.path.exists(output_file):
            os.chmod(output_file, stat.S_IRUSR | stat.S_IWUSR)
            os.remove(output_file) 
    
        return 0

class FeedbackHandler(StreamRequestHandler):

    # receive a block from socket, return data and errono
    # for errno: 
    # 0 for successfully, 
    # EFATAL for fatal error
    # EDISCONN for disconnection
    def readblock(self, expected_index):
        line = self.rfile.readline().strip()
        if not line:
            return EDISCONN, None
        tokens = line.split(':')
        if len(tokens) != 2:
            return EFATAL, None
        try:
            index = int(tokens[0])
            size = int(tokens[1])
        except:
            return EFATAL, None
        
        if expected_index != index:
            return EFATAL, None
    
        data = ''
        while size > 0:
            new_data = self.rfile.read(size)
            if not new_data:
                return EDISCONN, None
            size -= len(new_data)
            if not data:
                data = new_data
            else:
                data = data + new_data

        self.wfile.write('RECEIVED%d'%index)
        logger.debug("Block %d received"%index)
        return 0, data

    def handle(self):
            addr = self.request.getpeername()
            logger.debug('Get feedback from %s', addr)
            global CLUSTER_BEGIN_TIME
            if CLUSTER_BEGIN_TIME == 0:
                CLUSTER_BEGIN_TIME=time.time()

            stamp_1 = self.rfile.readline()
            if not stamp_1:
                logger.error("Some error happened: No job stamp received")
                sys.exit(1)
            stamp_1=stamp_1.strip()
            stamp_tokens = stamp_1.split('@')
            if (not stamp_tokens) or len(stamp_tokens) != 2 or stamp_tokens[0] != stamp:
                self.wfile.write("ERRJOB\n")
                logger.error("Some error happened: job stamp not matched")
                return
            self.wfile.write("BINGO\n")
            peer = stamp_tokens[1]
            global log_file
            log_fp = None
            if log_file:
                log_fp = file(log_file,'a')
            
            ok = False
            while True:
                line = self.rfile.readline()
                if line:
                    if line == "MAGIC\n":
                        global passwd_file
                        passwd_fd = open(passwd_file, "rb")
                        passwd_size = os.fstat(passwd_fd.fileno()).st_size
                        self.wfile.write("%d\n"%passwd_size)
                        while True:
                            passwd_data = passwd_fd.read(4096)
                            if not passwd_data:
                                break;
                            self.wfile.write(passwd_data)

                        passwd_fd.close()
                        if log_fp:
                            log_fp.close()
                            log_fp = None
                        return

                    if line == "tetsts\n":
                        logger.debug("""Cloning the workspace for you
It may take a few seconds depending on workspace size.
DO NOT ABORT PLEASE. COMING SOON ...
""")
                        while True:
                            data = self.rfile.read(4096)
                            if not data:
                                break
                            print data,
                            if log_fp:
                                log_fp.write(data)
                        if log_fp:
                            log_fp.close()
                            log_fp = None
                        return
 
                    if line == "testtaaa\n":
                        patch =  self.rfile.readline()

                        if (not patch) or len(patch) < 6:
                            if log_fp:
                                log_fp.close()
                                log_fp = None
                            logger.error("Unable to send patch file to compile cluster")
                            sys.exit(1)

                        patch = patch[5:].strip()
                        try:
                            patchno = int(patch)
                        except:
                            if log_fp:
                                log_fp.close()
                                log_fp = None
                            logger.error('"%s" not a patch number'%patch)
                            sys.exit(1)
                        patch_info = patch_list[patchno]
                        self.wfile.write("%s\n"%json.dumps(patch_info))
                        if patch_info['patchfile']:
                            patch_file = open(patch_info['patchfile'], "rb")
                            while True:
                                patch_data = patch_file.read(4096)
                                if not patch_data:
                                    break;
                                self.wfile.write(patch_data)

                            patch_file.close()
                            os.remove(patch_info['patchfile'])

                    elif line == "MAGIC0x6484\n":
                        if not BASH_FILE_NAME:
                            if log_fp:
                                log_fp.close()
                                log_fp = None
                            logger.error("Unable to send bash file to compile cluster")
                            sys.exit(1)

                        try:
                            bash_file = open(BASH_FILE_NAME,"rb")
                        except:
                            if log_fp:
                                log_fp.close()
                                log_fp = None
                            logger.error("Unable to open bash file %s for building"%BASH_FILE_NAME)
                            sys.exit(1)

                        bash_size = os.fstat(bash_file.fileno()).st_size
                        self.wfile.write("%d\n"%bash_size)
                        while True:
                            bash_data = bash_file.read(4096)
                            if not bash_data:
                                break;
                            self.wfile.write(bash_data)
                        bash_file.close()
                        logger.debug('Sent bash file %s to compile cluster ... [ ok ]'%BASH_FILE_NAME)
                    elif line == "MAGIC0x7368\n":
                        ok = True
                        break;
                    else:
                        print line,
                        if log_fp:
                            log_fp.write(line)
                        if line.startswith('[Notice]getprod@buildprod.scm.test.com:'):
                            build_addr = line[len('[Notice]'):]
                            if os.path.exists('build_info'):
                                shutil.copy('build_info','build_info.1')
                            build_info_fp = file('build_info','w')
                            build_info_fp.write('PRODUCT_PATH=%s'%build_addr)
                            build_info_fp.close()
                else:
                    break
        
            if log_fp:
                log_fp.close()
                log_fp = None

            if peer != "BUILDER":
                sys.exit(1)

            if not ok:
                return

            global CLUSTER_TRANS_TIME
            CLUSTER_TRANS_TIME=time.time()
            # We don't need output if job is on agl Jenkins
            if not is_on_AGLJENKINS():
                logger.debug('Ouput size is %s'%self.rfile.readline()[:-1])
                untar = UntarFile(self)
                result = untar.do()
                if result == 0:
                    logger.debug("Output received successfully.")
                else:
                    logger.error('Fail to receive output')
                    sys.exit(1)

            global CLUSTER_END_TIME
            CLUSTER_END_TIME=time.time()

            global JOB_END_TIME
            JOB_END_TIME=time.time()
            summary()
            # Should not use sys.exit(0) otherwise handle_error may be triggered.
            os._exit(0)

class Listener (TCPServer):
# set timeout here 
    timeout = 30
    timeout_count = 120
    def handle_error (self, request, client_address):
        sys.exit(1)

    def handle_timeout (self):
        global current_server, PORT
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        status_req = dict()
        status_req['ENV'] = env
        status_req['STAMP'] = stamp
        self.timeout_count -= 1
        if self.timeout_count <= 0:
            logger.error("Waitng for a long time. Please check your network")
            send_killed_meg()
            sys.exit(1)
        count = 0
        msg = None
        while count < 5:
            try:
                sock.connect((current_server, PORT))
                sock.send("STA%s\n"%json.dumps(status_req))
                msg = sock.recv(1024)
                sock.close()
            except:
                logger.warning('Loss of connection with scheduler. retrying......')
                count += 1
                time.sleep(10)
                continue
            break

        if msg == None:
            logger.error ('Loss of connection with scheduler. Please resubmit!')
            sys.exit(1)
 
        if msg.startswith('FAL'):
            logger.error ('FAIL: %s. Please resubmit!'%msg[3:])
            sys.exit(1)
        elif msg.startswith('SUC'):
            logger.info(msg[3:])
            if "Job has been dispatched" in msg[3:]:
                logger.warning('Build master connection timeout')
        else:
            logger.error ('Unexpected feedback from scheduler. Please resubmit!')
            sys.exit(1)

##################################################
# create a receiver to receive the build output 

def clean_log_file():
    global log_file
    if not os.path.exists(log_file):
        return
    os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)
    os.remove(log_file) 
    
def init_log():
    formatter=logging.Formatter("[%(asctime)s](%(levelname)s) : %(message)s")

    global log_file
    if not is_on_hudson():
        log_file='build_submitter.log'
        clean_log_file()
        handler=logging.handlers.RotatingFileHandler(log_file,maxBytes=100000000,backupCount=9)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
 
    handler=logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    logger.setLevel(logging.DEBUG)


def set_log_level():
    global debug_flag
    global logger
    if debug_flag:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logger.setLevel(log_level)

patch_list = list()

class CommandExcuter:
    def excute(self, command):
        logger.debug("Excute the command: %s",command)
        try:    
            pipe = subprocess.Popen(command,
                                    shell = True, stdout = subprocess.PIPE)
            pipe.wait()
        except:
            logger.error("Can not excute command: %s", command) 
            return None

        if pipe.returncode != 0:
            logger.error("ReturnCode is not 0, and the command is: %s", command) 
            return None
        output = ''
        while True:
            outputline = pipe.stdout.readline()
            if not outputline:
                break;
            output+=outputline[:-1]
        return output

def get_svn_url(path):
    return SvnInfoCommand(workspace=path).excute()

def is_text_file(f):
    if not os.path.exists(f):
        return False
    fd = open(f)
    buf = fd.read(100)
    for i in range(len(buf)):
        if buf[i] == '\0':
            return False
    return True

def generate_file_list(path):

    add_list = list()
    deleted_list = list()
    try:
        pipe = subprocess.Popen('cd %s && svn status -q --non-interactive'%path,
                                shell = True, stdout = subprocess.PIPE)
        logger.info("================files in patch================")
        while True:
            line = pipe.stdout.readline()
            if not line:
                break;
            file = line[7:].strip()
            if line[0] == 'M':
                add_list.append(file)
            elif line[0] == 'A':
                add_list.append(file)
            elif line[0] == 'R':
                add_list.append(file)
            elif line[0] == 'D':
                deleted_list.append(file)
            else:
                continue
            logger.info(line.strip())
        pipe.wait()
    except:
        logger.error('''Fail to run "svn status" on path %s'''%path)
        return False, None, None
    if pipe.returncode != 0:
        logger.error('''Fail to run "svn status" on path %s'''%path)
        return False, None, None

    return True, add_list, deleted_list

def generate_patch(path):

    global patch_list
    index = len(patch_list)
    
    patch_name = "build_submitter.patch%d"%index
    logger.debug("Generating diff for path %s"%path)

    ok, add_list, deleted_list = generate_file_list(path)

    if not ok:
        return None

    if not add_list and not deleted_list:
        return -1

    patch_info = dict()
    patch_info['deleted'] = deleted_list
    patch_info['patchfile'] = ''
    patch_info['patchsize'] = 0
    
    if add_list:
        patch_file = tarfile.open(patch_name, "w")
        saved_path = os.getcwd()
        os.chdir(path)
        for f in add_list:
            patch_file.add(f, recursive=False)
        os.chdir(saved_path)
        patch_file.close()
        patch_info['patchfile'] = patch_name
        patch_info['patchsize'] = os.stat(patch_name).st_size
    patch_list.append(patch_info)
    return index

def convert_local_path(path):
        
    if path.startswith('file://'):
        path=path[len('file://'):]
        
    if not os.path.exists(path):
        logger.error ('Unexisting path %s'%path)
        sys.exit(1)

    if not os.access(path, os.X_OK):
        logger.error ('Can not access path %s'%path)
        sys.exit(1)
        
    url = get_svn_url(path)
    if url == None:
        logger.error ('Fail to get svn url from %s'%path)
        sys.exit(1)

    patch_index = generate_patch(path)
    if patch_index == None:
        logger.error ('Fail to generate patch for %s'%path)
        sys.exit(1)
    elif patch_index >= 0:
        newurl = url + '@' + 'patch' + str(patch_index)
    else:
        logger.info("No diff found")
        newurl = url
    
    return True, newurl

def get_submitter_version(submitter_file):
    version = ''
    fp = file(submitter_file,'r')
    while True:
        data = fp.readline()
        if not data:
            break
        if data.startswith('VERSION='):
            version = data[len('VERSION='):].strip()
            break
        continue
    fp.close()
    if version:
        if version[0] == "'" or version[0] == '"':
            version = version[1:]
        if version[-1] == "'" or version[-1] == '"':
            version = version[:-1]
    return version

def get_remote_submitter(submitter_py):
    if os.path.exists(submitter_py) and os.path.getmtime(submitter_py) > os.path.getmtime(__file__):
        return True
    logger.info('Downloading the latest submitter from product repo ...')
    submitter_file='test/bin/build_submitter.py'
    if is_WindowsOS():
        submitter_file='test/bin/build_submitter.py'
    tmp_submitter_py='%s.%s.%d'%(submitter_py, time.time(), os.getpid())
    tmp_fp = open(tmp_submitter_py, 'wb')
    try:
        ftp = ftplib.FTP('product_test.scm.test.com')
        ftp.login('test', 'test')
        ftp.retrbinary('RETR ' + submitter_file, tmp_fp.write)
    except:
        ftp.quit()
        tmp_fp.close()
        if os.path.exists(tmp_submitter_py):
            os.chmod(tmp_submitter_py, stat.S_IRUSR | stat.S_IWUSR)
            os.remove(tmp_submitter_py)
        traceback.print_exc()
        logger.error('Fail to get the latest submitter from product repo')
        return False
    ftp.quit()
    tmp_fp.close() 
    
    global VERSION
    newest_version = get_submitter_version(tmp_submitter_py)
    if newest_version == VERSION:
        logger.error('Please check scheduler on version as it was newer than "%s" that product repo keeps'%newest_version)
        return False
    if os.path.exists(submitter_py):
        if os.path.getmtime(submitter_py) > os.path.getmtime(__file__):
            return True
        else:
            os.remove(submitter_py)
    os.rename(tmp_submitter_py,submitter_py)
    logger.info('Download ok. Cached it as %s'%submitter_py)
    return True

def restart_submitter(submitter_py): 
    logger.warning('Retrying with the cached submitter ...')
    saved_argv[0]=submitter_py 
    saved_argv.insert(0, sys.executable)
    pipe=subprocess.Popen(saved_argv)
    pipe.wait()
    os._exit(pipe.returncode)

def encrypt_login_info (username, passwd, hostname, hostip, public_key):
    encrypted_file = "%s%slogin.info.%s"%(submitter_dir, g_file_separator, username)
    try:
        pipe=subprocess.Popen('openssl rsautl -out "%s" -inkey "%s" -pubin -encrypt'%(encrypted_file, public_key), 
                              shell = True,
                              stdin = subprocess.PIPE)
        pipe.stdin.write(username + "\n" + passwd + "\n" + hostip + "\n" + hostname)
        pipe.stdin.close()
        pipe.wait()
    except:
        os.chmod(encrypted_file, stat.S_IRUSR | stat.S_IWUSR)
        os.remove(encrypted_file)
        return False
    if pipe.returncode != 0:
        os.chmod(encrypted_file, stat.S_IRUSR | stat.S_IWUSR)
        os.remove(encrypted_file)
        return False
    if os.path.exists(encrypted_file):
        os.chmod(encrypted_file, stat.S_IRUSR | stat.S_IWUSR)
        if is_WindowsOS():
            os.system('copy "%s" "%s\login.info" /Y' % (encrypted_file, submitter_dir))
        else:
            os.system("rm -f %s/login.info"%submitter_dir)
            os.symlink(encrypted_file,  "%s/login.info"%submitter_dir)
        global passwd_file
        passwd_file = encrypted_file
        return True
    else:
        return False

def recv_line(s):
    total_data = []; data = ''
    BUFSIZ=1024
    while True:
        data = s.recv(BUFSIZ, socket.MSG_PEEK)
        if not data:
            return None
        if "\n" in data:
            index = data.find("\n")
            total_data.append(data[:index])
            s.recv(index + 1)
            break
        else:
            s.recv(BUFSIZ)
        total_data.append(data)
    return ''.join(total_data)

def recv_file(f, sock, fsize):
    recv_size = 0
    while recv_size < fsize:
        if fsize - recv_size > 65536:
            data = sock.recv(65536)
        else:
            data = sock.recv(fsize - recv_size)
        if not data:
            break;
        recv_size += len(data)
        f.write(data)
    if recv_size != fsize:
        return False
    return True

def get_public_key():

    try:
        try:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.connect((SERVER, PORT))
        except socket.error, e:
            logger.info('Can not connect to scheduler, try the backup server ...')
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.connect((BACKUP_SERVER, PORT))
        # send request 'get public key' to scheduler
        sock.send('GPK\n')
        line = recv_line(sock)
    except:
        logger.error('Fail to connect to scheduler')     
        return None

    if not line:
        logger.error('Fail to get public key from scheduler')
        return None

    if not line.startswith('SUC'):
        logger.error('Fail to get public key from scheduler')     
        return None
    try:
        length = int(line[3:])
    except:
        logger.error('Fail to get length of public key')
        return None

    if is_WindowsOS():
        public_key_file = '%s\pubkey.%s.%d'%(os.environ['TEMP'], getpass.getuser(), os.getpid())
    else:
        public_key_file = '/tmp/pubkey.%d.%d'%(os.getuid(), os.getpid())
    public_key_fd = open(public_key_file, "w")
    if not recv_file(public_key_fd, sock, length):
        logger.error('Fail to get public key')
        public_key_fd.close()
        os.chmod(public_key_file, stat.S_IRUSR | stat.S_IWUSR)
        os.remove(public_key_file)
        return None
    public_key_fd.close()
    return public_key_file         

def do_svn_login():
    count = 0 
    username = None 
    while not username:
        print 'Svn user name:',
        username = sys.stdin.readline().strip()
        passwd = getpass.getpass() 
        tmpdir = '%s%ssvnlogin_%d'%(submitter_dir, g_file_separator, os.getpid())
        svn_url = 'https://svn.test.com/svnlogin'
        if is_on_hudson():
            svn_flags = '-N --no-auth-cache --non-interactive --trust-server-cert'
        else:
            svn_flags = '-N --non-interactive --trust-server-cert'
        svn_username = username.strip()
        svn_passwd = passwd
        svn_cmd_string = 'svn checkout %(svn_url)s "%(tmpdir)s" %(svn_flags)s'%(locals())
        svn_cmd_string += ' --username ' + str(username) + ' --password ' + str(passwd)

        try:
            pipe = subprocess.Popen(svn_cmd_string,
                                    stdout = subprocess.PIPE,
                                    stderr = subprocess.STDOUT,
                                    shell = True)
            pipe.wait()
        except:
            return None, None
        if os.path.exists(tmpdir):
            if is_WindowsOS():
                os.system('rmdir "%s" /S /Q'%tmpdir)
            else:
                shutil.rmtree(tmpdir)
        if pipe.returncode == 0:
            break
        if(count>=2):
            print '> Still failed'
            return None, None
        count=count+1
        username = None
        print '> Svn authorization failed, please try again...'
    return username, passwd

def do_git_login():
    print 'Git user name:',
    username = sys.stdin.readline().strip()
    passwd = getpass.getpass() 
    return username, passwd

def do_login(username = None, passwd = None, isgit=False):
    if not username:
        if not isgit:
            username, passwd = do_svn_login()
        else:
            username, passwd = do_git_login()
    hostname = socket.gethostname()
    hostip = socket.gethostbyname(hostname)
    public_key_file = get_public_key()
    if not public_key_file:
        return None
    result = encrypt_login_info(username, passwd, hostname, hostip, public_key_file)
    os.chmod(public_key_file, stat.S_IRUSR | stat.S_IWUSR)
    os.remove(public_key_file)
    if not result:
        logger.error('Fail to encrypt the svn account info')
        return None
    return username.strip()

def get_svn_info_from_file(svnfile, user):
    f = open(svnfile, "r")
    lines = f.readlines()
    f.close()
    key = None
    val = None
    if lines[-1] != "END\n":
        return None, None
    del lines[-1]
    num_lines = len(lines)
    if num_lines % 4 != 0:
        return None, None
    svn_info = dict()
    for i in range(0, num_lines, 4):
        if not lines[i].strip().startswith("K ") or not lines[i+2].strip().startswith("V "):
            return None, None
        svn_info[lines[i+1].strip()] = lines[i+3].strip()
    if svn_info.get("svn:realmstring") == None \
       or svn_info.get("svn:realmstring").find("https://svn.test.com:443") == -1:
        return None, None
    if svn_info.get("username") == None or svn_info.get("password") == None:
        return None, None
    if user and svn_info["username"] != user:
        return None, None
    return svn_info["username"], svn_info["password"]

def get_svn_account(user):
    svn_info_dir = "%s/.subversion/auth/svn.simple"%os.environ['HOME']
    if not os.path.exists(svn_info_dir):
        return None, None
    filelist = os.listdir(svn_info_dir)
    for f in filelist:
        if f.startswith("."):
            continue
        user, passwd = get_svn_info_from_file(os.path.join(svn_info_dir, f), user)
        if user and passwd:
            return user, passwd
    return None, None

def get_git_account(user):
    git_info_file = "%s/.netrc"%os.environ['HOME']
    if not os.path.exists(git_info_file):
        return None, None
    f = open(git_info_file, "r")
    lines = f.readlines()
    machine = ''
    gotuser = None
    gotpasswd = None
    for line in lines:
        line = line.strip()
        tokens = line.split()
        if len(tokens) == 2:
            if tokens[0] == 'machine':
                machine = tokens[1]
            if machine == GIT_MACHINE:
                if tokens[0] == 'login':
                    gotuser = tokens[1]
                if tokens[0] == 'password':
                    gotpasswd = tokens[1]
    if user:
        if gotuser == user:
            return gotuser, gotpasswd
        else:
            return None, None
    else:
        return gotuser, gotpasswd


def get_svn_passwd_file(user):
    svn_info_dir = "%s/.subversion/auth/svn.simple"%os.environ['HOME']
    if not os.path.exists(svn_info_dir):
        return None
    
    filelist = os.listdir(svn_info_dir)
    for f in filelist:
        if f.startswith("."):
            continue
        passwd_file = os.path.join(svn_info_dir, f)
        user, passwd = get_svn_info_from_file(passwd_file, user)
        if user and passwd:
            return passwd_file
    return None

def get_git_passwd_file(user):
    git_info_file = "%s/.netrc"%os.environ['HOME']
    if not os.path.exists(git_info_file):
        return None
    f = open(git_info_file, "r")
    lines = f.readlines()
    for line in lines:
        line = line.strip()
        tokens = line.split()
        if len(tokens) == 2 and tokens[0] == "login" and tokens[1] == user:
            return git_info_file
    return None

def get_user_passwd_file(user, git):
    if git:
        return get_git_passwd_file(user)
    else:
        return get_svn_passwd_file(user)

def send_killed_meg():
    global stamp
    global current_server, PORT
    try:
        killdata = dict()
        killdata['STAMP'] = stamp
        senddata='KIL%s\n'%(translate_listdata_to_json(killdata),)
        returndata=send_jsondata(senddata, current_server, PORT)
    except Exception as e:
        print e

def submitter_sig_handler (sig, stack):
    signal.signal (sig, signal.SIG_DFL)    
    send_killed_meg()
    os.kill(os.getpid(), sig)

def set_signal_handler ():    
    signal.signal(signal.SIGTERM, submitter_sig_handler)
    signal.signal(signal.SIGHUP, submitter_sig_handler)
    signal.signal(signal.SIGINT, submitter_sig_handler)

def check_writable():
    if not os.access('.', os.W_OK):
        print 'Current directory is NOT writeable'
        sys.exit(1)

def main():
    check_writable()
    global JOB_BEGIN_TIME
    JOB_BEGIN_TIME=time.time()

    init_log()
    global g_file_separator
    g_file_separator = "/"
    if is_WindowsOS():
        g_file_separator = "\\"

    global saved_argv
    saved_argv=copy.deepcopy(sys.argv)
    global submitter_dir
    if is_WindowsOS():
        submitter_dir='%s%s.build_submitter'%(os.environ['USERPROFILE'],g_file_separator)
    else:
        submitter_dir='%s%s.build_submitter'%(os.environ['HOME'],g_file_separator)
    if not os.path.exists(submitter_dir):
        os.mkdir(submitter_dir)
    if is_WindowsOS():
        submitter_py=os.path.realpath(__file__)
    else:
        submitter_py='%s%sbuild_submitter.py'%(submitter_dir,g_file_separator)
    if os.path.exists(submitter_py) and not is_WindowsOS():
        if os.path.getmtime(submitter_py) > os.path.getmtime(__file__):
            logger.warning('Found newer submitter in cache: %s'%submitter_py)
            restart_submitter(submitter_py)

    data=process_argvs()

    host = ''
    global receive_port
    port = receive_port
    global login_flag
    if login_flag == True:
        if not do_login():
            logger.error('Fail to store svn username and password')
            sys.exit(1)
        else:
            logger.info('Store svn username and password successfully')
            sys.exit(0)

    if not data:
        logger.error('Fail to process arguments')
        sys.exit(1)

    if os.getenv('PRE_SUBMIT_ID'):
        data['PRE_SUBMIT_ID'] = os.getenv('PRE_SUBMIT_ID')
        if data.get('MODULEPATH'):
            logger.info('-m in not allowed in pre-submit mode')
            sys.exit(1)
    
    if os.getenv('IGNORE_PRE_SUBMIT_COMMENT'):
        data['IGNORE_PRE_SUBMIT_COMMENT'] = True

    git = False
    if len(data['URL']) > 0 and data['URL'][0].startswith(GIT_REPO):
        git = True

    if is_on_hudson():
        data['JOB_NAME'] = os.getenv('JOB_NAME')
        data['BUILD_NUMBER'] = os.getenv('BUILD_NUMBER') 
    elif data.get('MODULEPATH') :
        logger.error("Are you going to release %s to test.scm? but Submitter couldn't get ENV variable $JOB_NAME or $BUILD_NUMBER." %(data['MODULEPATH']))
        sys.exit(1)

    if data.get('USER') == None and not is_on_hudson():
        data['USER'] = ""

    if is_on_AGLJENKINS():
        data['AGLJENKINS'] = '1'

    if data.get('USER') != None:
        user = data['USER'].strip()
        # verify if login info file exists
        global passwd_file
        if user == "":
            passwd_file = "%s%slogin.info"%(submitter_dir, g_file_separator)
        else:
            passwd_file = "%s%slogin.info.%s"%(submitter_dir, g_file_separator, user)

        if not is_WindowsOS():
            user_passwd_file = get_user_passwd_file(user, git)
            if os.path.exists(passwd_file) \
               and user_passwd_file and os.path.exists(user_passwd_file) \
               and os.stat(passwd_file).st_mtime < os.stat(user_passwd_file).st_mtime:
                print("Passwd changed, remove saved passwd %s"%passwd_file)
                if os.path.islink(passwd_file):
                    real_passwd_file = os.readlink(passwd_file)
                    if not real_passwd_file.startswith('/'):
                        real_passwd_file = os.path.join(passwd_file, real_passwd_file)
                    os.remove(real_passwd_file)
                    os.remove(passwd_file)
                else:
                    os.remove(passwd_file)
                
        if not os.path.exists(passwd_file):
            if not is_WindowsOS():
                if not git:
                    print("File %s does not exist, trying to get svn account info from %s/.subversion"%(passwd_file, os.environ['HOME']))
                    user, passwd = get_svn_account(user)
                else:
                    print("File %s does not exist, trying to get git account info from %s/.netrc"%(passwd_file, os.environ['HOME']))
                    user, passwd = get_git_account(user)

                if not user:
                    if not git:
                        print("Fail to get svn account info from %s/.subversion, please login with your svn account"%(os.environ['HOME']))
                    else:
                        print("Fail to get git account info from %s/.netrc, please login with your git account"%(os.environ['HOME']))
                         
                    user = do_login(isgit=git)
                    if not user:
                        logger.error('Fail to store username and password')
                        sys.exit(1)
                else:
                    do_login(user, passwd, isgit=git)
            else:
                print("logging into compiler cluster...")
                user = do_login()

            data['USER'] = user
            passwd_file = "%s%slogin.info.%s"%(submitter_dir, g_file_separator, user)
            logger.debug('Store svn username and password successfully')

    logger.debug("Submitter is starting ...")
    count = 100
    while count > 0:
        try:
            server = Listener ((host, port), FeedbackHandler)
            break;
        except socket.error:
            logger.warning("can not create a listener on port %s", port)
            count = count - 1
            port = port + 1
    if count == 0:
        logger.error("fail to create a socket server")
        sys.exit (1)
    logger.debug("listening on port %s", port)
    if not is_on_hudson():
        server.timeout_count = 2
    data['PORT'] = port

    # stamp is a unique ID of this job
    m = hashlib.md5()
    m.update(json.dumps(data) + str(time.time()))
    data['STAMP'] = m.hexdigest()
    global stamp
    stamp = data['STAMP']

    global env
    env = data['ENV']

    global outputs
    outputs = data['OUTPUT']

    data['CC_ARGS'] = ' '.join(saved_argv[1:])

    data['IVERSION']=VERSION
    if(is_on_hudson()):
        if 'HUDSON_URL' in os.environ:
            data['HUDSON'] = os.environ['HUDSON_URL']
        else:
            data['HUDSON'] = ''

    if (len(data['CMD']) == 1) and (data['CMD'][0] == 'sh ._scm_autobuild.sh' or data['CMD'][0] == 'sh bd.sh' or data['CMD'][0] == 'sh Rbd.sh'):
        data['SCM_AUTOBUILD']=""

    for i in range(6):
        try:
            logger.debug('Submitting a job request to compile cluster...')
            logger.info(json.dumps(data,sort_keys=True,indent=4))
            senddata='REQ%s\n'%(translate_listdata_to_json(data),)
            global current_server
            if SERVER == DEF_SERVER:
                try:
                    current_server = SERVER
                    returndata=send_jsondata(senddata, current_server, PORT)
                except socket.error, e:
                    logger.warning('Can not connect to scheduler, try the backup server ...')
                    current_server = BACKUP_SERVER
                    returndata=send_jsondata(senddata, current_server, PORT)
            else:
                current_server = SERVER
                returndata=send_jsondata(senddata, current_server, PORT)
            break
        except:
            if i == 5:
                logger.error('[FATAL] Failed to send compiler data,please contact scm, hi group: 1354895')
                sys.exit(1)
            logger.warning('[WARNING] Failed to send compiler data ! Sleep 5s...try again.')
            time.sleep(5)

    if returndata.startswith('FAL'):
        if returndata.__contains__('UNMATCHED-VERSION'):
            logger.warning(returndata[3:])
            if get_remote_submitter(submitter_py) == False:
                sys.exit(1)
            server.server_close()
            restart_submitter(submitter_py)
        else:
            logger.error(returndata[3:])
        sys.exit(1)
    elif returndata.startswith('SUC'):
        logger.debug(returndata[3:])
    else:
        logger.error('Unexpected feedback from scheduler')
        sys.exit(1)

    cache_cmdline(saved_argv)
    set_signal_handler()
    while True:
        server.handle_request()

if __name__ == '__main__':
    main()

logging.shutdown()

