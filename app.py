from flask import Flask, jsonify
import asyncio
import aiohttp
from aiohttp import ClientSession, TCPConnector
import re
import BannerData_pb2
from google.protobuf.json_format import MessageToDict
from cachetools import TTLCache
import logging
from functools import wraps

# Configurações
app = Flask(__name__)
cache = TTLCache(maxsize=100, ttl=28000)  # Cache com TTL de 8 horas (~28800 segundos)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Pool de conexões persistentes
connector = TCPConnector(
    limit=100,  # Número máximo de conexões simultâneas
    keepalive_timeout=300,  # Manter conexões abertas por 5 minutos
    force_close=False,
    enable_cleanup_closed=True
)

# Decorator para cache
def cached_async(cache_key):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if cache_key in cache:
                logger.info(f"Retornando dados do cache para {cache_key}")
                return cache[cache_key]
            
            result = await func(*args, **kwargs)
            cache[cache_key] = result
            return result
        return wrapper
    return decorator

# Funções otimizadas
async def pegar_jwt(session: ClientSession, uid: str, password: str) -> tuple:
    """Obtém o token JWT com conexão persistente."""
    url = f"https://aditya-jwt-v9op.onrender.com/token?uid={uid}&password={password}"
    try:
        async with session.get(url, timeout=5) as resp:
            if resp.status == 200:
                dados = await resp.json()
                return dados.get("token", ""), dados.get("serverUrl", "https://client.us.freefiremobile.com")
            logger.error(f"Erro ao obter JWT: Status {resp.status}")
    except Exception as e:
        logger.error(f"Erro na requisição JWT: {str(e)}")
    return "", "https://client.us.freefiremobile.com"

@cached_async("splash_data")
async def get_splash_data(session: ClientSession, token: str, server_url: str) -> dict:
    """Obtém os dados de splash com tratamento robusto."""
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

    try:
        async with session.post(
            f"{server_url}/LoginGetSplash",
            headers=headers,
            data=data,
            timeout=10
        ) as resp:
            resposta_binaria = await resp.read()
            return decodificar_protobuf(resposta_binaria)
    except Exception as e:
        logger.error(f"Erro na requisição splash: {str(e)}")
        return {"erro": str(e)}

def decodificar_protobuf(dados_binarios: bytes) -> dict:
    """Decodifica protobuf com fallback para texto."""
    try:
        msg = BannerData_pb2.RootMessage()
        msg.ParseFromString(dados_binarios)
        return MessageToDict(msg, preserving_proto_field_name=True)
    except Exception as e:
        logger.warning(f"Falha ao decodificar Protobuf: {str(e)}")
        return {"erro": "Falha ao decodificar Protobuf", "fallback": filtrar_por_hex(dados_binarios)}

def filtrar_por_hex(resposta_bytes: bytes) -> str:
    """Filtra bytes imprimíveis de forma otimizada."""
    return re.sub(r'\s+', ' ', ''.join(
        chr(b) if (0x20 <= b <= 0x7E) or (0xA0 <= b <= 0xFF) else ' '
        for b in resposta_bytes
    )).strip()

# Rota principal otimizada
@app.route("/splash", methods=["GET"])
async def splash_endpoint():
    """Endpoint principal com todas as otimizações."""
    uid = "3743593901"
    password = "07B3A66A0FEF912E2CF0194EF606D26C3581FB4F5E225B814208C6076DB19F90"
    
    try:
        async with ClientSession(connector=connector) as session:
            # Obter token (com timeout curto)
            token, server_url = await asyncio.wait_for(
                pegar_jwt(session, uid, password),
                timeout=5
            )
            
            if not token:
                return jsonify({"erro": "Token JWT não encontrado"}), 500
            
            # Obter dados (com timeout maior)
            dados = await asyncio.wait_for(
                get_splash_data(session, token, server_url),
                timeout=15
            )
            
            return jsonify(dados)
    except asyncio.TimeoutError:
        logger.error("Timeout nas operações")
        return jsonify({"erro": "Timeout ao processar requisição"}), 504
    except Exception as e:
        logger.error(f"Erro inesperado: {str(e)}")
        return jsonify({"erro": "Erro interno no servidor"}), 500

# Inicialização
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
