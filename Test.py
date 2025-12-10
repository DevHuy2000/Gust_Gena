import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp , asyncio
from protobuf_decoder.protobuf_decoder import Parser
from flask import Flask, request, jsonify
from xC4 import *
from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad 
import random 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# Optimized Global Variables
online_writer = None
whisper_writer = None
bot_start_time = time.time()
connection_pool = None
# Variables set in MaiiiinE and used by perform_random_emote
key = None
iv = None
region = None 
loop = None 

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': 'v1 1',
    'ReleaseVersion': "OB51"
}

# Random Color Function (Giữ lại nếu muốn)
def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]", "[7CFC00]", "[B22222]",
        "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]", "[DDA0DD]", "[E6E6FA]",
        "[2E8B57]", "[3CB371]", "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]"
    ]
    return random.choice(colors)

# Helper function (SEndPacKeT is used in the new logic)
async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT):
    global online_writer, whisper_writer
    # Dùng online_writer cho 'OnLine' packet
    if TypE == 'OnLine' and online_writer: 
        online_writer.write(PacKeT) 
        await online_writer.drain()
    # Dùng whisper_writer cho 'ChaT' packet (Giữ lại để logic không bị lỗi, mặc dù không dùng)
    elif TypE == 'ChaT' and whisper_writer: 
        whisper_writer.write(PacKeT) 
        await whisper_writer.drain()
    else: 
        # Không cần return string nếu không dùng trong chat
        return 

# Crypto, Login, and Auth functions (kept as is)
async def encrypted_proto(encoded_hex):
    key_aes = b'Yg&tc%DEuh6%Zc^8'
    iv_aes = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key_aes, AES.MODE_CBC, iv_aes)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
 
    try:
        async with connection_pool.post(url, headers=Hr, data=data) as response:
            if response.status != 200: 
                return "Failed to get access token"
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
   
            return (open_id, access_token) if open_id and access_token else (None, None)
    except:
        return (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.118.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return  await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    try:
        async with connection_pool.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: 
                return await response.read()
            return None
    except:
        return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
 
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization']= f"Bearer {token}"
    try:
        async with connection_pool.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: 
                return await response.read()
            return None
    except:
       return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto
    
async def xAuThSTarTuP(TarGeT, token, timestamp, key_arg, iv_arg):
    # ... logic của xAuThSTarTuP
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key_arg, iv_arg)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    # ... logic header
    if uid_length == 9: 
        headers = '0000000'
    elif uid_length == 8: 
        headers = '00000000'
    elif uid_length == 10: 
        headers = '000000'
    elif uid_length == 7: 
        headers = '000000000'
    else: 
        print('Unexpected length') 
        headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"

# TCP connection tasks
async def TcPOnLine(ip, port, AutHToKen, reconnect_delay=0.5):
    global online_writer, key, iv
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                # Đọc dữ liệu nhưng không xử lý
                data2 = await reader.read(9999) 
                if not data2: 
                    break
            online_writer.close() 
            await online_writer.wait_closed() 
            online_writer = None

        except Exception as e: 
            print(f"- ErroR With {ip}:{port} (Online) - {e}")
            online_writer = None
        await asyncio.sleep(reconnect_delay)

async def TcPChaT(ip, port, AutHToKen, LoGinDaTaUncRypTinG, ready_event, reconnect_delay=0.5):
    global whisper_writer 
    print(region, 'TCP CHAT') 

    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            
            # Logic Clan Auth (Nếu cần) - Dựa vào source cũ, giữ lại cấu trúc
            if LoGinDaTaUncRypTinG.Clan_ID: 
               # Giả sử AuthClan sử dụng key/iv toàn cục
               clan_id = LoGinDaTaUncRypTinG.Clan_ID
               clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
               # pK = await AuthClan(clan_id , clan_compiled_data , key , iv) 
               # if whisper_writer: 
               #    whisper_writer.write(pK) 
               #    await whisper_writer.drain()

            # Loop đọc dữ liệu CHAT (KHÔNG xử lý lệnh chat)
            while True:
                data = await reader.read(9999) 
                if not data: 
                    break
                
            whisper_writer.close() 
            await whisper_writer.wait_closed() 
            whisper_writer = None
            
        except Exception as e: 
            print(f"ErroR {ip}:{port} (Chat) - {e}") 
            whisper_writer = None
        await asyncio.sleep(reconnect_delay)

# --------------------------------------------------
app = Flask(__name__)

# Danh sách Emote ID cho chức năng RANDOM (Lấy từ source [cite: 79, 80])
LIST_EMOTES = [ 
    909040010, 909000063, 909035007, 909000085, 909000090,
    909000098, 909045001, 909000081, 909039011, 909049010,
    909039011, 909038010, 909042008, 909041005, 909033002
]

async def perform_random_emote(team_code: str, uids: list):
    global key, iv, region, online_writer
    
    if online_writer is None:
        raise Exception("Bot not connected (online_writer is None)")

    try:
        # Bước 1: Vào Team [cite: 84]
        join_packet = await GenJoinSquadsPacket(team_code, key, iv) # Đã sửa self.key/iv -> key/iv
        await SEndPacKeT(None, None, 'OnLine', join_packet)
        await asyncio.sleep(2)  # Đợi 2 giây để vào phòng [cite: 86]

        # Bước 2: Chạy Loop hết danh sách Emote cho tất cả UIDs [cite: 88]
        count_sent = 0
        for emote_id in LIST_EMOTES:
            for target_uid_str in uids: 
                try:
                    target_uid = int(target_uid_str) # Đảm bảo UID là int
                    H = await Emote_k(target_uid, emote_id, key, iv, region) # Đã sửa self.key/iv/region -> key/iv/region
                    await SEndPacKeT(None, None, 'OnLine', H) # Gửi gói tin Emote
                except Exception as e:
                    print(f"Error sending emote {emote_id} to {target_uid_str}: {e}")
                    pass
            
            count_sent += 1
            await asyncio.sleep(5.5) # Delay giữa các emote cho toàn bộ nhóm [cite: 95]

        # Bước 3: Rời Team ngay lập tức [cite: 96]
        leave_packet = await ExiT(None, key, iv) # Đã sửa self.key/iv -> key/iv
        await SEndPacKeT(None, None, 'OnLine', leave_packet)
        
        return {"status": "success", "message": f"Random emote sequence complete! Sent: {count_sent} emote types.", "emote_types": len(LIST_EMOTES), "targets": len(uids)}
    except Exception as e:
        print(f"Failed to perform random emote: {str(e)}")
        raise Exception(f"Failed to perform random emote: {str(e)}")

@app.route('/random_emote')
def random_emote_api():
    global loop
    team_code = request.args.get('tc')
    uids_raw = [request.args.get(f'uid{i}') for i in range(1, 7)]

    if not team_code:
        return jsonify({"status": "error", "message": "Missing required parameter: tc (team_code)"}), 400

    uids = [uid for uid in uids_raw if uid and uid.isdigit()]

    if not uids:
        return jsonify({"status": "error", "message": "At least one valid UID (uid1..uid6) must be provided"}), 400

    try:
        # Chạy coroutine trong threadpool của asyncio loop
        asyncio.run_coroutine_threadsafe(
            perform_random_emote(team_code, uids), loop
        )
        
        return jsonify({
            "status": "triggered",
            "team_code": team_code,
            "uids_targetted": uids,
            "emote_types": len(LIST_EMOTES),
            "message": "Random emote sequence has been triggered asynchronously. The bot will join the team, execute the sequence, and leave."
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

def run_flask():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)


async def MaiiiinE():
    global connection_pool, loop, key, iv, region
    # Enhanced connection pool configuration
    connection_pool = aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=20),
        connector=aiohttp.TCPConnector(limit=20, limit_per_host=10)
    )
    
    Uid , Pw = '4333606824','BY_PARAHEX-K171DVRMG-REDZED'
    
    open_id , access_token = await GeNeRaTeAccEss(Uid , Pw)
    if not open_id or not access_token: 
        print("ErroR - InvaLid AccounT") 
        return None
    
    PyL = await EncRypTMajoRLoGin(open_id , access_token) 
    MajoRLoGinResPonsE = await MajorLogin(PyL) 
    if not MajoRLoGinResPonsE: 
        print("TarGeT AccounT => BannEd / NoT ReGisTeReD !") 
        return None
    
    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE) 
    UrL = MajoRLoGinauTh.url
    print(UrL)
    region = MajoRLoGinauTh.region # Set global region
    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key # Set global key
    iv = MajoRLoGinauTh.iv # Set global iv
    timestamp = MajoRLoGinauTh.timestamp
    
    # Lấy loop trước khi tạo task
    loop = asyncio.get_running_loop() 

    LoGinDaTa = await GetLoginData(UrL , PyL , ToKen) 
    if not LoGinDaTa: 
        print("ErroR - GeTinG PorTs From LoGin DaTa !") 
        return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa) 
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP , OnLineporT = OnLinePorTs.split(":")
    ChaTiP , ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName
    print(ToKen)
    # equie_emote(ToKen,UrL)
    AutHToKen = await xAuThSTarTuP(int(TarGeT) , ToKen , int(timestamp) , key , iv)
    ready_event = asyncio.Event()
    
    # TcPChaT không cần key/iv trong tham số
    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT , AutHToKen , LoGinDaTaUncRypTinG , ready_event))
     
    await ready_event.wait()
    await asyncio.sleep(1)
    # TcPOnLine không cần key/iv trong tham số
    task2 = asyncio.create_task(TcPOnLine(OnLineiP , OnLineporT , AutHToKen)) 
    os.system('clear')
    print(render('SGCODEX', colors=['white', 'green'], align='center'))
    print('')
    print(f" - SGCODEX BOT STarTinG And OnLine on TarGet : {TarGeT} | BOT NAME : {acc_name}\n") 
    print(f" - BoT sTaTus > GooD | OnLinE ! (:")    
    print(f" - SGCODEX | Bot Uptime: {time.strftime('%H:%M:%S', time.gmtime(time.time() - bot_start_time))}")    

    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    await asyncio.gather(task1 , task2)
    
async def StarTinG(): 
    while True:
        try: 
            await asyncio.wait_for(MaiiiinE() , timeout = 7 * 60 * 60)
        except asyncio.TimeoutError: 
            print("Token ExpiRed ! , ResTartinG")
        except Exception as e: 
            print(f"ErroR TcP - {e} => ResTarTinG ...")

if __name__ == '__main__':
    asyncio.run(StarTinG())