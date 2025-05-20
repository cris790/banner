import asyncio
import aiohttp
import re
import BannerData_pb2  # Arquivo gerado via protoc
from google.protobuf.json_format import MessageToDict

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

async def pegar_token():
    url = "seu link do token"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            dados = await resp.json()
            if isinstance(dados, list) and len(dados) > 0:
                return dados[0].get("token", "")
            elif isinstance(dados, dict):
                return dados.get("token", "")
            return ""

def decodificar_protobuf(dados_binarios):
    """Decodifica os bytes usando o esquema do BannerData.proto"""
    msg = BannerData_pb2.RootMessage()
    msg.ParseFromString(dados_binarios)
    return MessageToDict(msg, preserving_proto_field_name=True)

async def main():
    print("Pegando token...")
    token = await pegar_token()
    print(f"Token obtido: {token}")

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
            print(f"Status da resposta: {resp.status}")
            resposta_binaria = await resp.read()
            with open("resposta.bin", "wb") as f:
                f.write(resposta_binaria)

    print("Decodificando resposta Protobuf...")
    try:
        dados = decodificar_protobuf(resposta_binaria)
        print("\nResposta Protobuf decodificada:\n")
        import json
        print(json.dumps(dados, indent=2, ensure_ascii=False))
        with open("resposta.json", "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[ERRO] Falha ao decodificar Protobuf: {e}")
        print("\nFallback (visualização filtrada):\n")
        print(filtrar_por_hex(resposta_binaria))

if __name__ == "__main__":
    asyncio.run(main())
