import re
import socket
import threading
import select
import time

#--------------
locker = False

#-------

SOCKS_VERSION = 5

server_chang=False
singafora= False
mena=False
Th=False

invit_spam=False
command=True
benfit = False
spams = False
spampacket= b''
recordmode= False
sendpackt=False
spy = False

SOCKS_VERSION = 5
packet =b''
spaming =False
op = None



class Proxy:
    def __init__(self):
        self.username = "ysn-bot"
        self.password = "ysn99ryn"

    def handle_client(self, connection):
        # greeting header
        # read and unpack 2 bytes from a client
        version, nmethods = connection.recv(2)

        # get available methods [0, 1, 2]
        methods = self.get_available_methods(nmethods, connection)

        # accept only USERNAME/PASSWORD auth
        if 2 not in set(methods):
            # close connection
            connection.close()
            return

        # send welcome message
        connection.sendall(bytes([SOCKS_VERSION, 2]))

        if not self.verify_credentials(connection):
            return

        # request (version=5)
        version, cmd, _, address_type = connection.recv(4)

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)

        # convert bytes to unsigned short array
        port = int.from_bytes(connection.recv(2), 'big', signed=False)

        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)



                if server_chang==True:

                    #serves ip
                    if port==39698 : #39698
                        address="23.90.159.146"

                    if port==39800:
                        address="23.90.159.202"


                if singafora==True:


                    if port==39698 : #39698
                        address="202.181.76.150"

                    if port==39800:
                        address="202.181.76.143"
                if Th==True:


                    if port==39698 : #39698

                        if "10" in address:
                            address="202.181.72.40"
                        elif "22" in address:
                            address="202.181.72.41"
                        else:
                            address="202.181.72.44"

                    if port==39800:

                        address="202.181.72.62"



                if mena==True:
                    if port==39698 : #39698

                        address="23.90.158.18"

                    if port==39800:

                        address="23.90.158.118"






                remote.connect((address, port))


                bind_address = remote.getsockname()
                print("* Connected to {} {}".format(address, port))
            else:
                connection.close()

            addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
            port = bind_address[1]

            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')
            ])
        except Exception as e:
            # return connection refused error
            print(e)
            reply = self.generate_failed_reply(address_type, 5)

        connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:

            self.exchange_loop(connection, remote)

        connection.close()


    def exchange_loop(self, client, remote):
        while True:
            # wait until client or remote is available for read
            try:
                r, w, e = select.select([client, remote], [], [])
            except:
                break
            global singafora ,don,mena,Th, server_chang ,port_conect_39698 , port_conect_39800
            global hide
            global packet
            global op,locker
            
            global recordmode , command    ,spy ,invit_spam

            if client in r:
                try:
                    data = client.recv(4096)
                except:
                    break
                if  "39698" in str(remote) :
                    self.op = remote
                if '0515' in data.hex()[0:4] and len(data.hex()) >=820 and invit_spam==True :
                    try:
                        for i in range(2):
                            threading.Thread(target=spam__invite , args=(data , remote)).start()
     
                    except Exception as a:
                        print(e)
                        pass

                if '1215' in data.hex()[0:4] and recordmode ==True:
                    b = threading.Thread(target=spam, args=(remote,data))
                    b.start()
                if '0515' in data.hex()[0:4] and len(data.hex()) >= 141:
                    hide = True
                if  "39698" in str(remote) :
                    op = remote

                
                try  :
                    if remote.send(data) <= 0:
                        if "39800" in str(remote):
                            port_conect_39800=remote
                        if "3969" in str(remote):
                            port_conect_39698=remote

                        break
                except:
                    break
            if remote in r:
                try:
                    data = remote.recv(4096)
                except:
                    break                    #-----------------------------------------------------------------------------------------------------
                if "39800" in str(remote):
                    port_conect_39800=remote
                if "3969" in str(remote):
                    port_conect_39698=remote
                if  '0500' in data.hex()[0:4] and hide == True :
                    if len(data.hex())<=30:
                        hide =True
                    if len(data.hex())>=31:
                        packet = data
                        hide = False
                if  '0f00' in data.hex()[0:4] and spy==True :
                    client.send(packet)
                            #-------------------------------------------------------------------
            #----------------- LEVEL BOT DISABLED BECAUSE OF BUGS -----------------------------
           #  if b'/lvl' in data and "0315" in data.hex()[0:4] and len(data.hex())>820:
             #    print("Detected")
             #    self.start_game=data
            #     threading.Thread(target=self.level_up ).start()
           #      print("Sending in empty")
           #      self.op.send(bytes.fromhex("031500000010091eb74eef39b7574e359602b0670ca8"))
             #    self.op.send(bytes.fromhex("031500000010091eb74eef39b7574e359602b0670ca8031500000010091eb74eef39b7574e359602b0670ca8"))
                #-------------------------------------------------------------------------------            
                try:
                    if client.send(data) <= 0:
                        break
                except:
                    break

                if '1200' in data.hex()[0:4] and command==True:
                    if b'/spy-ysn' in data:
                        spy=True
                        client.send(bytes.fromhex(gen_msgv2(data.hex() ,"[E0FF00]SPY: [00FF00]ON")))
                        client.send(bytes.fromhex(str(gen_msgv2_clan(data.hex() ,"[E0FF00]SPY: [00FF00]ON"))))
                    if b'/-spy' in data:
                        spy=False
                        client.send(bytes.fromhex(gen_msgv2(data.hex() ,"[E0FF00]SPY: [FF0000]OFF")))
                        client.send(bytes.fromhex(str(gen_msgv2_clan(data.hex() ,"[E0FF00]SPY: [FF0000]OFF"))))
                    if b'/inv-ysn' in data:
                        invit_spam=True
                        client.send(bytes.fromhex(gen_msgv2(data.hex() ,"[E0FF00]INVITE SPAMMER: [00FF00]ON")))
                        client.send(bytes.fromhex(str(gen_msgv2_clan(data.hex() ,"[E0FF00]INVITE SPAMMER: [00FF00]ON"))))
                    if b'/-inv' in data:
                        invit_spam=False
                        client.send(bytes.fromhex(gen_msgv2(data.hex() ,"[E0FF00]INVITE SPAMMER: [FF0000]OFF")))
                        client.send(bytes.fromhex(str(gen_msgv2_clan(data.hex() ,"[E0FF00]INVITE SPAMMER: [FF0000]OFF"))))
                    if b'/sp-ysn' in data:
                        recordmode=True
                        client.send(bytes.fromhex(gen_msgv2(data.hex() ,"[E0FF00]CHAT SPAMMER: [00FF00]ON")))
                        client.send(bytes.fromhex(str(gen_msgv2_clan(data.hex() ,"[E0FF00]CHAT SPAMMER: [00FF00]ON"))))
                    if b'/-sp' in data:
                        recordmode=False
                        client.send(bytes.fromhex(gen_msgv2(data.hex() ,"[E0FF00]CHAT SPAMMER: [00FF00]OFF")))
                        client.send(bytes.fromhex(str(gen_msgv2_clan(data.hex() ,"[E0FF00]CHAT SPAMMER: [00FF00]OFF"))))
                    if b'/5s-ysn' in data:
                    	locker = True
                if '1200' in data.hex()[0:4] and locker==True:
                    client.send(bytes.fromhex(str(gen_msgv2_clan(data.hex() ,"[00FF00] 5 IN SQUAD ON"))))
                    op.send(bytes.fromhex("0503000001d01fb578313150905babcef51dd24ed75fd0a24b024bd1429646114bc22e604afd35a96fbc48710b2d9cfec4378287ec829e33a78608fd2dd138d4d24a19c00fbfdc9f15c77ff86d638b34de95bd886e3075e82d3f4a3888f9b6943463022c43fb90e229f0eaf8a788f6f766d891d99eb2c37b277144923212810b3c80d1c521790154ed270f5241adc136f2a22816e0bc84fcaf79386b27559de966aa788c184d35bbbfaa03a5f08746f8db0e73b2c91ec4515d61f689a0cad30a7cbd6c325151e879dabc43d506b3240abe41bc0d6b4416c18f68ef4af2d04c381be6bf586f6b25727c0c85c03a579137e4a6c602ef6d833dabdab3eba3a5266e5a4731fbfb1720b60f124cd8fd4fa26cc7a9fb6e0a218d8809f57b204d22fa97520aeb99007c7b71c709e53ecc688c9963e0786909152fa93f06dc93085468dae34e1609f33f7dee228fb058c6efd6846b50ac54db0aebb8f5bc2f6751f9e2886dbab41cbaf5a1d8cd88e6c13a2a2a56b613a2d32179dc3f781493a5027322ac0cb1a2d3c79d49fb12ed26230e1561df43d315a27be17b5debdba757803305252b5443f3d77cd319dde9c49a72c636d93d02bdd9597168f378aa6e41d0fd545abf8bc0883f3dac11ea27166683c7111a0f329bf6b6a5"))
                

                if '1200' in data.hex()[0:4] :
                    if b'/EU' in data:
                        server_chang=True
                        singafora=False
                        Th=False
                        mena=False
                        pyload_3 = gen_msgv2_clan(data.hex() , "[FF0000]CLORETS BOT \n\n[00FF00]Server ON.")
                        client.send(bytes.fromhex(pyload_3))
                        client.send(bytes.fromhex(gen_msgv2(data.hex() , "[FF0000]CLORETS BOT \n\n[00FF00]Server ON.")))
                        time.sleep(5)
                        try:
                            port_conect_39698.close()
                            port_conect_39800.close()
                        except:
                            pass
                    if b'/SG' in data:
                        server_chang=False
                        singafora=True
                        Th=False
                        mena=False
                        pyload_3 = gen_msgv2_clan(data.hex() , "[FF0000]CLORETS BOT \n\n[00FF00]Server ON.")
                        client.send(bytes.fromhex(str(pyload_3)))
                        client.send(bytes.fromhex(gen_msgv2(data.hex() , "[FF0000]CLORETS BOT \n\n[00FF00]Server ON.")))
                        time.sleep(5)
                        try:
                            port_conect_39698.close()
                            port_conect_39800.close()
                        except:
                            pass

                    if b'/ME' in data:
                        server_chang=False
                        singafora=False
                        Th=False
                        mena=True
                        pyload_3 = gen_msgv2_clan(data.hex() , "[FF0000]CLORETS BOT \n\n[00FF00]Server ON.")
                        client.send(bytes.fromhex(str(pyload_3)))                  #                            T                           T
                        client.send(bytes.fromhex(str(gen_msgv2(data.hex() , "[FF0000]CLORETS BOT \n\n[00FF00]Server ON."))))
                        time.sleep(5)
                        try:
                            port_conect_39698.close()
                            port_conect_39800.close()
                        except:
                            pass


                    if b'/TH' in data:
                        server_chang=False
                        singafora=False
                        mena=False
                        Th=True
                        pyload_3 = gen_msgv2_clan(data.hex() , "[FF0000]CLORETS BOT \n\n[00FF00]Server ON.")
                        client.send(bytes.fromhex(pyload_3))
                        client.send(bytes.fromhex(gen_msgv2(data.hex() , "[FF0000]CLORETS BOT \n\n[00FF00]Server ON.")))
                        time.sleep(5)
                        try:
                            port_conect_39698.close()
                            port_conect_39800.close()
                        except:
                            pass




                if "1200" in data.hex()[0:4]:
                    if b"/id" in data:
                        user_id= (bytes.fromhex(re.findall(r'6964(.*?)28' , data.hex()[50:])[0])).decode("utf-8")

                        threading.Thread(target=getinfobyid , args=(data.hex() , user_id , client)).start()

    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])


    def verify_credentials(self, connection):

        version = ord(connection.recv(1)) # should be 1


        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode('utf-8')

        password_len = ord(connection.recv(1))

        password = connection.recv(password_len).decode('utf-8')

        if username  and password :
            # success, status = 0
            response = bytes([version, 0])
            connection.sendall(response)
            return True

        # failure, status != 0
        response = bytes([version, 0xFF])
        connection.sendall(response)
        connection.close()
        return False


    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods

    def run(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()

        print("* Bot is running on  {}:{} ...".format(host, port))

        while True:
            conn, addr = s.accept()

            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()
    def level_up(self):

        time.sleep(10)
        print("start")
        self.op.send(bytes.fromhex("031500000010091eb74eef39b7574e359602b0670ca8"))
        self.op.send(bytes.fromhex("031500000010091eb74eef39b7574e359602b0670ca8031500000010091eb74eef39b7574e359602b0670ca8"))

        while self.spam_level==True :

            self.op.send(self.start_game)
            self.op.send(self.start_game)
            print("Sending in function")
            self.op.send(bytes.fromhex("031500000010091eb74eef39b7574e359602b0670ca8"))
            self.op.send(bytes.fromhex("031500000010091eb74eef39b7574e359602b0670ca8031500000010091eb74eef39b7574e359602b0670ca8"))

            time.sleep(10)
def spam(server,packet):
    while True:
        time.sleep(0.012)
        server.send(packet)
        global recordmode
        if  recordmode ==False:
            break
def spam__invite(data ,remote): 
    global invit_spam
    
    try:
        while invit_spam==True:
            time.sleep(0.0012)
            remote.send(data)
    except:
        pass
def str2hex(s:str):
    return ''.join([hex(ord(c))[2:].zfill(2) for c in s])

def get_info(user_id):
	global ff_player_region,requests,json
	import requests,json

	id = user_id
	cookies = {

        '_ga': 'GA1.1.2123120599.1674510784',
        '_fbp': 'fb.1.1674510785537.363500115',
        '_ga_7JZFJ14B0B': 'GS1.1.1674510784.1.1.1674510789.0.0.0',
        'source': 'mb',
        'region': 'MA',
        'language': 'ar',
        '_ga_TVZ1LG7BEB': 'GS1.1.1674930050.3.1.1674930171.0.0.0',
        'datadome': '6h5F5cx_GpbuNtAkftMpDjsbLcL3op_5W5Z-npxeT_qcEe_7pvil2EuJ6l~JlYDxEALeyvKTz3~LyC1opQgdP~7~UDJ0jYcP5p20IQlT3aBEIKDYLH~cqdfXnnR6FAL0',
        'session_key': 'efwfzwesi9ui8drux4pmqix4cosane0y',
    }

	headers = {
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        # 'Cookie': '_ga=GA1.1.2123120599.1674510784; _fbp=fb.1.1674510785537.363500115; _ga_7JZFJ14B0B=GS1.1.1674510784.1.1.1674510789.0.0.0; source=mb; region=MA; language=ar; _ga_TVZ1LG7BEB=GS1.1.1674930050.3.1.1674930171.0.0.0; datadome=6h5F5cx_GpbuNtAkftMpDjsbLcL3op_5W5Z-npxeT_qcEe_7pvil2EuJ6l~JlYDxEALeyvKTz3~LyC1opQgdP~7~UDJ0jYcP5p20IQlT3aBEIKDYLH~cqdfXnnR6FAL0; session_key=efwfzwesi9ui8drux4pmqix4cosane0y',
        'Origin': 'https://shop2game.com',
        'Referer': 'https://shop2game.com/app/100067/idlogin',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi Note 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
        'accept': 'application/json',
        'content-type': 'application/json',
        'sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'x-datadome-clientid': '6h5F5cx_GpbuNtAkftMpDjsbLcL3op_5W5Z-npxeT_qcEe_7pvil2EuJ6l~JlYDxEALeyvKTz3~LyC1opQgdP~7~UDJ0jYcP5p20IQlT3aBEIKDYLH~cqdfXnnR6FAL0',
    }

	json_data = {
        'app_id': 100067,
        'login_id': f'{id}',
        'app_server_id': 0,
    }

	res = requests.post('https://shop2game.com/api/auth/player_id_login', cookies=cookies, headers=headers, json=json_data)
	response = json.loads(res.text)
	try :
		name=response['nickname']
		region = response["region"]
		name = [name,region]
		ff_player_region =name[1]
	except:
		pass
	return name[0]
def convert_to_bytes(input_string):
    # replace non-hexadecimal character with empty string
    cleaned_string = input_string[:231] + input_string[232:]
    # convert cleaned string to bytes
    output_bytes = bytes.fromhex(cleaned_string)
    return output_bytes
def gen_msgv2(packet  , replay):

    replay  = replay.encode('utf-8')
    replay = replay.hex()


    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:60]

    pyloadlength = packet[60:62]#
    pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
    pyloadTile = packet[int(int(len(pyloadtext))+62):]


    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)

    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2))  )+ int(len(replay)//2) )[2:]

    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile

    return str(finallyPacket)


def check_information(uid,abbr):
	player_uid = uid

	servers_name_db = {
	"bd": "Bangladesh",
	"br": "Brazil",
	"eu": "Europe",
	"hk": "Hong Kong",
	"id": "Indonesia",
	"in": "India",
	"me": "Middle East",
	"mo": "Macau",
	"my": "Malaysia",
	"ph": "Philippines",
	"pk": "Pakistan",
	"ru": "Russia",
	"sa": "Latin America",
	"sg": "Singapore",
	"th": "Thailand",
	"tw": "Taiwan",
	"vn": "Vietnam",
	"ind" : "India"
	}
	def get_server_name(abbr):
		short_name = abbr.lower()
		return servers_name_db[short_name]
	try:
		player_server = get_server_name(abbr)
	except:
		player_server = abbr
	def check_if_banned(uid):
		response_bol = None
		request_url = f"https://ff.garena.com/api/antihack/check_banned?lang=en&uid={uid}"
		req_server = requests.get(request_url)
		req_response = req_server.text
		req_response = json.loads(req_response)
		if req_response["status"]=="success":
			formula = req_response["data"]["is_banned"]
			if formula==1:
				response_bol=True
			elif formula==0:
				response_bol=False
		return response_bol
	def return_result(res_bol):
		if res_bol:
			return "[FF0000]Account is Banned"
		elif res_bol==False:
			return "[00FF00]Account is Clean"
	msg = return_result(check_if_banned(uid))
	return (player_server,msg)

def getinfobyid(packet , user_id , client):
    player_name = get_info(user_id)
    player_region = ff_player_region
    received_data = check_information(user_id,player_region)
    final_info_region = received_data[0]
    final_ban_msg = received_data[1]
#--------------------------------------------------
    payload_3 = gen_msgv2_clan(packet , f"[00FF00]{player_name}")
    client.send(bytes.fromhex(payload_3))
    payload_3 = gen_msgv2(packet , f"[00FF00]{player_name}")
    client.send(bytes.fromhex(payload_3))
    payload_4 = gen_msgv2_clan(packet,f"[1108ED]Player Server : [ECB746]{final_info_region}")
    client.send(bytes.fromhex(payload_4))
    payload_4 = gen_msgv2_clan(packet,final_ban_msg)
    client.send(bytes.fromhex(payload_4))

    payload_5 = gen_msgv2(packet,f"[1108ED]Player Server : [ECB746]{final_info_region}")
    client.send(bytes.fromhex(payload_5))
    payload_5 = gen_msgv2(packet,final_ban_msg)
    client.send(bytes.fromhex(payload_5))





def gen_msgv2_clan(packet  , replay):

    replay  = replay.encode('utf-8')
    replay = replay.hex()

    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:64]
    pyloadlength = packet[64:66]#
    pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
    pyloadTile = packet[int(int(len(pyloadtext))+66):]
    


    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)
    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]


    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile

    return (finallyPacket)



Proxy().run('127.0.0.1',1080)



