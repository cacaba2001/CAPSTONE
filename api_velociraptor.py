import requests,urllib3,argparse, os
from base64 import b64encode
from dotenv import load_dotenv
load_dotenv() # load from environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # skip warrning SSL

#get basic authentication token
def get_token(username, password):
    token = b64encode(f"{username}:{password}".encode('utf-8')).decode("ascii")
    return f'Basic {token}'

#global parameters
username=os.getenv('VELO_USERNAME')
password=os.getenv('VELO_PASSWORD')
notebook_id=os.getenv('notebook_id')
cell_id=os.getenv('cell_id')
urlCreateAndRunNoteBookCell =os.getenv('urlCreateAndRunNoteBookCell') #https://{velociraptor_host}:{port}/api/v1/UpdateNotebookCell
urlGetGorilla_csrf_token = os.getenv('urlGetGorilla_csrf_token') #https://{velociraptor_host}:{port}/app/index.html
urlGetX_Csrf_Token = os.getenv('urlGetX_Csrf_Token') #https://{velociraptor_host}:{port}/api/v1/GetHunt
headers = {"Content-type":"application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0", "Accept": "application/json, text/plain, */*", "Accept-Language": "vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Authorization": get_token(username, password), "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "Te": "trailers"}

#get new gorilla_csrf_token
def get_gorilla_csrf_token(my_headers):
    rs=requests.get(urlGetGorilla_csrf_token, headers=my_headers,verify=False)
    gorilla_csrf_token=rs.headers['Set-Cookie'].split(";")[0].split("_gorilla_csrf=")[1]
    return {"_gorilla_csrf":gorilla_csrf_token}

#get new X_Csrf_Token
def get_X_Csrf_Token(my_headers,my_cookie):
    rs=requests.get(urlGetX_Csrf_Token, headers=my_headers, cookies=my_cookie,verify=False)
    X_Csrf_Token=rs.headers['X-Csrf-Token']
    return X_Csrf_Token

#get new CSRF_Token set
def get_new_CSRF_Token(my_headers):
    rs=[]
    rs.append(get_gorilla_csrf_token(my_headers))
    rs.append(get_X_Csrf_Token(my_headers,rs[0]))
    return rs

#Token not change after each login skip this function
def check_connection(headers):
    test_url = "https://101.96.111.196:8889/api/v1/GetUserUITraits"
    result=requests.get(test_url, headers=headers, verify=False)# add verify=False to Accept risk(trust CER)
    if result.status_code == 200:
        print('[+]Connected!')
        return True
    else:
        print('[+]Connect Failed!')
        return False
        
#LOGIN
def login(username, password):
    print("login!!")
#Get input from user
def get_input():
    description="""
        THIS SCRIPT IS USED TO CREATE "HUNT" ON "VELOCIRAPTOR" SERVER.
    """
    parser = argparse.ArgumentParser(description=description)
    # add agrs from user
    parser.add_argument('-u',dest='username',help=': Username of velociraptor server (not required)',required=False)
    parser.add_argument('-p',dest='password',required=False,help=': Password of velociraptor server (not required)')
    parser.add_argument('-P',dest='payload',required=True,help=': VQL query')
    parser.add_argument('-t',choices=['vql', 'markdown'],default='vql',help=': Notebook type')
    parser.add_argument('-os',choices=['deb', 'win'],default='win',help=': Client operating system')
    dict_agrs = vars(parser.parse_args())
    #print(dict_agrs)
    #maybe can do with regex(skip os)
    if dict_agrs["os"]=='deb':
        dict_agrs["payload"]= dict_agrs["payload"].replace("spec=dict(Linux.Sys.BashShell","spec=dict(`Linux.Sys.BashShell`")
    else:
        dict_agrs["payload"]= dict_agrs["payload"].replace("spec=dict(Windows.System.PowerShell","spec=dict(`Windows.System.PowerShell`")
    #print()
    #print("Input:")
    return dict_agrs
#create a hunt in velociraptor server
def execute_command(headers,agrs):
    check_connect=check_connection(headers)
    if not check_connect:
        headers=login(agrs['username'], 'password')
    json_body={"cell_id": cell_id, "currently_editing": False, 'input': agrs["payload"], "notebook_id": notebook_id, "type": agrs["t"]}
    list_of_csrf_token_set=get_new_CSRF_Token(headers)
    headers["X-Csrf-Token"]=list_of_csrf_token_set[1]
    rs=requests.post(urlCreateAndRunNoteBookCell,cookies=list_of_csrf_token_set[0], headers=headers,json=json_body,verify=False)
    #print(agrs["payload"])
    #print("##################################################")
    #print(rs.text)
    if "VQL Error" in rs.text:
        print("[+]Check your VQL query!!!")
        print('[!]************VQL QUERY************[!]')
        print(agrs["payload"])
        print('[!]************VQL QUERY************[!]')
    else:
        print("[+]Execute successfully")

if __name__ == "__main__":
    execute_command(headers,get_input())
