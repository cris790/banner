from flask import Flask, jsonify, request
import asyncio
import aiohttp
import re
import BannerData_pb2  # Seu arquivo .proto compilado
from google.protobuf.json_format import MessageToDict

app = Flask(__name__)

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

async def pegar_jwt(uid, password):
    url = f"https://aditya-jwt-v9op.onrender.com/token?uid={uid}&password={password}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            dados = await resp.json()
            if "token" in dados:
                return dados["token"], dados.get("serverUrl", "https://client.us.freefiremobile.com")
            return "", "https://client.us.freefiremobile.com"

def decodificar_protobuf(dados_binarios):
    msg = BannerData_pb2.RootMessage()
    msg.ParseFromString(dados_binarios)
    return MessageToDict(msg, preserving_proto_field_name=True)

async def executar_logica():
    # Dados fixos conforme seu exemplo
    uid = "3743593901"
    password = "07B3A66A0FEF912E2CF0194EF606D26C3581FB4F5E225B814208C6076DB19F90"
    
    token, server_url = await pegar_jwt(uid, password)
    if not token:
        return {"erro": "Token JWT não encontrado"}, 500

    url_post = f"{server_url}/LoginGetSplash"
    headers = {
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": "OB49",
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
    resultado = asyncio.run(executar_logica())
    return jsonify(resultado)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
