from flask import Flask, jsonify, request
import asyncio
import aiohttp
import re
import BannerData_pb2  # Seu arquivo .proto compilado
from google.protobuf.json_format import MessageToDict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

app = Flask(__name__)

def get_credentials(region):
    """Retorna UID e password com base na região"""
    region = region.upper()
    if region == "IND":
        return "3938172055", "ADITYA_FREE_INFO_IND"
    elif region in ["NA", "BR", "SAC", "US"]:
        return "3938172433", "ADITYA_FREE_INFO_NA"
    else:
        return "3938172267", "ADITYA_FREE_INFO_SG"

async def get_jwt_token(region):
    """Obtém token JWT para a região especificada"""
    uid, password = get_credentials(region)
    url = f"https://genjwt.vercel.app/api/get_jwt?type=4&guest_uid={uid}&guest_password={password}"
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            return data.get('BearerAuth')

def filtrar_por_hex(resposta_bytes):
    """Filtra bytes imprimíveis e Latin1."""
    filtrado = []
    for b in resposta_bytes:
        if (0x20 <= b <= 0x7E) or (0xA0 <= b <= 0xFF):
            filtrado.append(chr(b))
        else:
            filtrado.append(' ')
    texto = ''.join(filtrado)
    return re.sub(r'\s+', ' ', texto).strip()

def decodificar_protobuf(dados_binarios):
    """Decodifica dados binários Protobuf para dicionário"""
    msg = BannerData_pb2.RootMessage()
    msg.ParseFromString(dados_binarios)
    return MessageToDict(msg, preserving_proto_field_name=True)

async def fetch_splash_data(region):
    """Busca dados do splash screen para a região especificada"""
    token = await get_jwt_token(region)
    if not token:
        return {"erro": "Falha ao obter token JWT"}, 500

    url_post = "https://client.us.freefiremobile.com/LoginGetSplash"
    headers = {
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": "OB48",
        "X-GA": "v1 1",
        "Authorization": f"Bearer {token}",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 6.0.1; ASUS_Z01QD Build/V417IR)",
        "Host": "client.us.freefiremobile.com",
    }

    data = b"\xA5\xE1\x89\x0E\xE5\x83\xC7\xDF\x22\xA0\x5F\x2E\x7C\xCF\xFE\xE2"

    async with aiohttp.ClientSession() as session:
        async with session.post(url_post, headers=headers, data=data) as resp:
            resposta_binaria = await resp.read()

    try:
        dados = decodificar_protobuf(resposta_binaria)
        return dados
    except Exception as e:
        texto_fallback = filtrar_por_hex(resposta_binaria)
        return {"erro": "Falha ao decodificar Protobuf", "fallback": texto_fallback}

@app.route("/splash", methods=["GET"])
def splash_endpoint():
    """Endpoint principal para obter dados do splash screen"""
    region = request.args.get('region', 'US').upper()
    if region not in ["IND", "NA", "BR", "SAC", "US", "SG"]:
        return jsonify({"error": "Região inválida. Use IND, NA, BR, SAC, US ou SG"}), 400
    
    resultado = asyncio.run(fetch_splash_data(region))
    
    # Adiciona créditos e informações adicionais
    if not isinstance(resultado, dict) or 'erro' in resultado:
        return jsonify(resultado), 500
    
    resultado['credit'] = 'SeuCréditoAqui'  # Adicione seus créditos
    resultado['region'] = region
    return jsonify(resultado)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
