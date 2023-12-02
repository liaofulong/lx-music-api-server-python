#!/usr/bin/env python3


from logging import Logger
from aiohttp import web
import json
import traceback
import time
from common import config
from common import lxsecurity
from common import Httpx
from apis import SongURL
from common import utils

Httpx.checkcn()

app = web.Application()

async def index(request):
    return web.json_response({"code": 0, "msg": "success", "data": None})

async def handle(request):
    method = request.match_info.get('method', '')
    source = request.match_info.get('source', '')
    songId = request.match_info.get('songId', '')
    quality = request.match_info.get('quality', '')

    if (config.read_config("security.key.enable") and request.host.split(':')[0] not in config.read_config('security.whitelist_host')):
        if (request.headers.get("X-Request-Key")) != config.read_config("security.key.value"):
            if (config.read_config("security.key.ban")):
                config.ban_ip(request.remote_addr)
            return web.json_response({"code": 1, "msg": "key验证失败", "data": None}, status=403)

    if (config.read_config('security.check_lxm.enable') and request.host.split(':')[0] not in config.read_config('security.whitelist_host')):
        lxm = request.headers.get('lxm')
        if (not lxsecurity.checklxmheader(lxm, request.url)):
            if (config.read_config('security.lxm_ban.enable')):
                config.ban_ip(request.remote_addr)
            return web.json_response({"code": 1, "msg": "lxm请求头验证失败", "data": None}, status=403)

    if method == 'url':
        try:
            response_data = await SongURL(source, songId, quality)
            return web.json_response(response_data)
        except Exception as e:
            Logger.error(traceback.format_exc())
            return web.json_response({'code': 4, 'msg': '内部服务器错误', 'data': None}, status=500)
    else:
        return web.json_response({'code': 6, 'msg': f'未知的请求类型: {method}', 'data': None}, status=400)

app.router.add_get('/', index)
app.router.add_get('/{method}/{source}/{songId}/{quality}', handle)

web.run_app(app, host=config.read_config('common.host'), port=config.read_config('common.port'))