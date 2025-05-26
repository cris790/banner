from flask import Flask, jsonify, request
import asyncio
import aiohttp
import re
import BannerData_pb2
from google.protobuf.json_format import MessageToDict
from datetime import datetime

app = Flask(__name__)

# Configurações
REQUEST_TIMEOUT = 15
MAX_RETRIES = 2
REGIONS = {
    "BR": {"domain": "br", "credentials": ("3938172433", "ADITYA_FREE_INFO_NA")},
    "US": {"domain": "us", "credentials": ("3938172433", "ADITYA_FREE_INFO_NA")},
    "IND": {"domain": "ind", "credentials": ("3938172055", "ADITYA_FREE_INFO_IND")},
    "SG": {"domain": "sg", "credentials": ("3938172267", "ADITYA_FREE_INFO_SG")}
}

class SplashService:
    @staticmethod
    async def get_jwt_token(region):
        """Obtém token JWT com retry automático"""
        uid, password = REGIONS[region]["credentials"]
        url = f"https://genjwt.vercel.app/api/get_jwt?type=4&guest_uid={uid}&guest_password={password}"
        
        async with aiohttp.ClientSession() as session:
            for attempt in range(MAX_RETRIES + 1):
                try:
                    async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return data.get('BearerAuth')
                        elif attempt == MAX_RETRIES:
                            return None
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    if attempt == MAX_RETRIES:
                        return None
                await asyncio.sleep(1)  # Espera antes de tentar novamente

    @staticmethod
    async def fetch_splash_data(region):
        """Busca dados de splash com fallback para outras regiões"""
        token = await SplashService.get_jwt_token(region)
        if not token:
            return {"error": "Failed to get JWT token after retries"}, 500

        # Tenta primeiro a região solicitada
        result = await SplashService._try_region(region, token)
        if not result.get("error"):
            return result

        # Se falhar, tenta outras regiões como fallback
        for fallback_region in [r for r in REGIONS if r != region]:
            result = await SplashService._try_region(fallback_region, token)
            if not result.get("error"):
                result["warning"] = f"Using data from {fallback_region} as fallback"
                return result

        return {"error": "All regions failed"}, 502

    @staticmethod
    async def _try_region(region, token):
        """Tenta obter dados de uma região específica"""
        domain = REGIONS[region]["domain"]
        url = f"https://client.{domain}.freefiremobile.com/LoginGetSplash"
        headers = {
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "ReleaseVersion": "OB48",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {token}",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 6.0.1; ASUS_Z01QD Build/V417IR)",
            "Host": f"client.{domain}.freefiremobile.com",
        }

        data = b"\xA5\xE1\x89\x0E\xE5\x83\xC7\xDF\x22\xA0\x5F\x2E\x7C\xCF\xFE\xE2"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, data=data, timeout=REQUEST_TIMEOUT) as resp:
                    if resp.status != 200:
                        return {"error": f"Server {domain} returned HTTP {resp.status}"}
                    
                    content = await resp.read()
                    
                    # Verifica se é uma resposta HTML de erro
                    if content.startswith(b'<html>') or content.startswith(b'<!DOCTYPE html>'):
                        return {"error": f"Server {domain} returned HTML error page"}
                    
                    # Tenta decodificar como Protobuf
                    try:
                        msg = BannerData_pb2.RootMessage()
                        msg.ParseFromString(content)
                        return MessageToDict(msg, preserving_proto_field_name=True)
                    except Exception as e:
                        return {"error": f"Failed to decode Protobuf from {domain}: {str(e)}"}

        except asyncio.TimeoutError:
            return {"error": f"Timeout when accessing {domain}"}
        except aiohttp.ClientError as e:
            return {"error": f"Connection error to {domain}: {str(e)}"}

@app.route("/splash", methods=["GET"])
def splash_endpoint():
    """Endpoint principal para obter dados de splash"""
    region = request.args.get('region', 'US').upper()
    
    if region not in REGIONS:
        return jsonify({
            "status": "error",
            "message": "Invalid region specified",
            "valid_regions": list(REGIONS.keys()),
            "timestamp": datetime.utcnow().isoformat()
        }), 400
    
    result, status_code = asyncio.run(SplashService.fetch_splash_data(region))
    
    response = {
        "status": "error" if "error" in result else "success",
        "region": region,
        "timestamp": datetime.utcnow().isoformat(),
        "credit": "YourNameHere"
    }
    
    if "error" in result:
        response.update({
            "error": result["error"],
            "details": result.get("fallback", "No additional details")
        })
        if "warning" in result:
            response["warning"] = result["warning"]
    else:
        response["data"] = result
    
    return jsonify(response), status_code

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
